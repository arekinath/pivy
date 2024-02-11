/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <strings.h>
#include <limits.h>
#include <err.h>

#include "debug.h"

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>
#include <sys/errno.h>
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/authfd.h"

#include "sss/hazmat.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(__sun)
#include <libtecla.h>
#else
#include <editline/readline.h>
#endif

#include <libcryptsetup.h>
#include <json.h>

#include "tlv.h"
#include "errf.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include "ebox-cmd.h"

static struct ebox_tpl *lukstpl;
static size_t luks_sectorsz;

#define	lukserrf(func, rc)	\
    errfno(func, (-1*rc), NULL)

static void usage(void);

static errf_t *
unlock_or_recover(struct ebox *ebox, const char *descr, boolean_t *recovered)
{
	struct ebox_config *config;
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	struct ebox_tpl_config *tconfig;
	errf_t *error;
	struct question *q = NULL;
	struct answer *a;
	struct ans_config *ac;
	char k = '0';

	/* Try to use the pivy-agent to unlock first if we have one. */
	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) == EBOX_PRIMARY) {
			part = ebox_config_next_part(config, NULL);
			tpart = ebox_part_tpl(part);
			error = local_unlock_agent(ebox_part_box(part));
			if (error) {
				errf_free(error);
				continue;
			}
			error = ebox_unlock(ebox, config);
			if (error)
				return (error);
			*recovered = B_FALSE;
			goto done;
		}
	}

	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) == EBOX_PRIMARY) {
			part = ebox_config_next_part(config, NULL);
			tpart = ebox_part_tpl(part);
			error = local_unlock(ebox_part_box(part),
			    ebox_tpl_part_cak(tpart),
			    ebox_tpl_part_name(tpart));
			if (error && !errf_caused_by(error, "NotFoundError"))
				return (error);
			if (error) {
				errf_free(error);
				continue;
			}
			error = ebox_unlock(ebox, config);
			if (error)
				return (error);
			*recovered = B_FALSE;
			goto done;
		}
	}

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Recovery mode --\n");
	question_printf(q, "No primary configuration could proceed using a "
	    "token currently available\non the system. You may either select "
	    "a primary config to retry, or select\na recovery config to "
	    "begin the recovery process.\n\n");
	question_printf(q, "Select a configuration to use:");
	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		ac = ebox_config_alloc_private(config, sizeof (*ac));
		VERIFY(ac != NULL);
		a = calloc(1, sizeof (*a));
		VERIFY(a != NULL);
		ac->ac_ans = a;
		ac->ac_config = config;
		a->a_key = ++k;
		a->a_priv = ac;
		make_answer_text_for_config(tconfig, a);
		add_answer(q, a);
	}
again:
	question_prompt(q, &a);
	ac = a->a_priv;
	config = ac->ac_config;
	tconfig = ebox_config_tpl(config);
	if (ebox_tpl_config_type(tconfig) == EBOX_PRIMARY) {
		part = ebox_config_next_part(config, NULL);
		tpart = ebox_part_tpl(part);
		release_context();
		error = local_unlock(ebox_part_box(part),
		    ebox_tpl_part_cak(tpart),
		    ebox_tpl_part_name(tpart));
		if (error) {
			warnfx(error, "failed to activate config %c", a->a_key);
			errf_free(error);
			goto again;
		}
		error = ebox_unlock(ebox, config);
		if (error)
			return (error);
		*recovered = B_FALSE;
		goto done;
	}
	error = interactive_recovery(config, descr);
	if (error) {
		warnfx(error, "failed to activate config %c", a->a_key);
		errf_free(error);
		goto again;
	}
	error = ebox_recover(ebox, config);
	if (error)
		return (error);

	*recovered = B_TRUE;

done:
	question_free(q);
	return (ERRF_OK);
}

static void
cmd_rekey(const char *devname)
{
	struct crypt_device *cd;
	int rc;
	const uint8_t *key;
	size_t keylen;
	struct sshbuf *buf;
	char *b64, *descr;
	const char *b64i;
	size_t desclen;
	boolean_t recovered;
	const char *json;
	json_object *jv, *obj;
	struct ebox *ebox, *nebox;
	errf_t *error;

	rc = crypt_init(&cd, devname);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_init", rc), "failed to "
		    "open device '%s'", devname);
	}

	rc = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_load", rc), "failed to "
		    "load info from device '%s'", devname);
	}

	rc = crypt_token_json_get(cd, 1, &json);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_token_json_get", rc),
		    "failed to load ebox from device '%s'", devname);
	}

	obj = json_tokener_parse(json);
	if (obj == NULL)
		errx(EXIT_ERROR, "failed to parse json");

	jv = json_object_object_get(obj, "type");
	if (jv == NULL) {
		errx(EXIT_ERROR, "no 'type' property in LUKS token json?");
	}
	if (strcmp("ebox", json_object_get_string(jv)) != 0) {
		errx(EXIT_ERROR, "expected ebox token in slot 1, found '%s'",
		    json_object_get_string(jv));
	}

	jv = json_object_object_get(obj, "ebox");
	if (jv == NULL) {
		errx(EXIT_ERROR, "no 'ebox' property in LUKS token json");
	}
	b64i = json_object_get_string(jv);

	/* We use this string for the recovery flavour text. */
	desclen = strlen(devname) + 128;
	descr = calloc(1, desclen);
	snprintf(descr, desclen, "LUKS device %s", devname);

	buf = sshbuf_new();
	if (buf == NULL)
		err(EXIT_ERROR, "failed to allocate buffer");
	if ((rc = sshbuf_b64tod(buf, b64i))) {
		error = ssherrf("sshbuf_b64tod", rc);
		errfx(EXIT_ERROR, error, "failed to parse LUKS token data "
		    "from %s as base64", devname);
	}
	if ((error = sshbuf_get_ebox(buf, &ebox))) {
		errfx(EXIT_ERROR, error, "failed to parse LUKS token data "
		    "from %s as a valid ebox", devname);
	}

	fprintf(stderr, "Attempting to unlock device '%s'...\n", devname);
	(void) mlockall(MCL_CURRENT | MCL_FUTURE);
	if ((error = unlock_or_recover(ebox, descr, &recovered)))
		errfx(EXIT_ERROR, error, "failed to unlock ebox");

	key = ebox_key(ebox, &keylen);

	if (lukstpl == NULL) {
		lukstpl = ebox_tpl_clone(ebox_tpl(ebox));
	}

	error = ebox_create(lukstpl, key, keylen, NULL, 0, &nebox);
	if (error)
		errfx(EXIT_ERROR, error, "ebox_create failed");
	sshbuf_reset(buf);
	error = sshbuf_put_ebox(buf, nebox);
	if (error)
		errfx(EXIT_ERROR, error, "sshbuf_put_ebox failed");

	b64 = sshbuf_dtob64_string(buf, 0);

	json_object_object_add(obj, "ebox", json_object_new_string(b64));

	rc = crypt_token_json_set(cd, 1, json_object_to_json_string(obj));
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_token_json_set", rc),
		    "failed to set metadata on device '%s'", devname);
	}

	free(b64);
	sshbuf_free(buf);
	ebox_free(ebox);
	ebox_free(nebox);
	crypt_free(cd);
}

static void
cmd_unlock(const char *devname, const char *mapperdev)
{
	struct crypt_device *cd;
	int rc;
	const uint8_t *key;
	size_t keylen;
	struct sshbuf *buf;
	char *b64, *descr;
	const char *b64i;
	size_t desclen;
	boolean_t recovered;
	char *line;
	const char *json;
	json_object *jv, *obj;
	struct ebox *ebox, *nebox;
	struct ebox_tpl *ntpl;
	struct ebox_tpl_config *tconfig;
	struct ebox_tpl_part *tpart;
	errf_t *error;

	rc = crypt_init(&cd, devname);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_init", rc), "failed to "
		    "open device '%s'", devname);
	}

	if (crypt_status(cd, devname) == CRYPT_ACTIVE) {
		errx(EXIT_ALREADY_UNLOCKED, "device '%s' already unlocked "
		    "and active", devname);
	}

	rc = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_load", rc), "failed to "
		    "load info from device '%s'", devname);
	}

	rc = crypt_token_json_get(cd, 1, &json);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_token_json_get", rc),
		    "failed to load ebox from device '%s'", devname);
	}

	obj = json_tokener_parse(json);
	if (obj == NULL)
		errx(EXIT_ERROR, "failed to parse json");

	jv = json_object_object_get(obj, "type");
	if (jv == NULL) {
		errx(EXIT_ERROR, "no 'type' property in LUKS token json?");
	}
	if (strcmp("ebox", json_object_get_string(jv)) != 0) {
		errx(EXIT_ERROR, "expected ebox token in slot 1, found '%s'",
		    json_object_get_string(jv));
	}

	jv = json_object_object_get(obj, "ebox");
	if (jv == NULL) {
		errx(EXIT_ERROR, "no 'ebox' property in LUKS token json");
	}
	b64i = json_object_get_string(jv);

	/* We use this string for the recovery flavour text. */
	desclen = strlen(devname) + 128;
	descr = calloc(1, desclen);
	snprintf(descr, desclen, "LUKS device %s", devname);

	buf = sshbuf_new();
	if (buf == NULL)
		err(EXIT_ERROR, "failed to allocate buffer");
	if ((rc = sshbuf_b64tod(buf, b64i))) {
		error = ssherrf("sshbuf_b64tod", rc);
		errfx(EXIT_ERROR, error, "failed to parse LUKS token data "
		    "from %s as base64", devname);
	}
	if ((error = sshbuf_get_ebox(buf, &ebox))) {
		errfx(EXIT_ERROR, error, "failed to parse LUKS token data "
		    "from %s as a valid ebox", devname);
	}

	fprintf(stderr, "Attempting to unlock device '%s'...\n", devname);
	(void) mlockall(MCL_CURRENT | MCL_FUTURE);
	if ((error = unlock_or_recover(ebox, descr, &recovered)))
		errfx(EXIT_ERROR, error, "failed to unlock ebox");

	key = ebox_key(ebox, &keylen);

	rc = crypt_activate_by_volume_key(cd, mapperdev, (char *)key,
	    keylen, 0);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_activate_by_volume_key", rc),
		    "failed to activate device '%s'", devname);
	}

	if (recovered) {
		fprintf(stderr, "-- Add new primary configuration --\n");
		fprintf(stderr, "If the original primary PIV token has been "
		    "lost or damaged, it is recommended\nthat you add a new "
		    "primary token now. You can then use `pivy-luks rekey' "
		    "later\nto remove the old primary device.\n\n");
ynagain:
		line = readline("Add new primary now? [Y/n] ");
		if (line == NULL)
			exit(EXIT_ERROR);
		if (line[0] == '\0' || (line[1] == '\0' &&
		    (line[0] == 'Y' || line[0] == 'y'))) {
			free(line);
			goto newprimary;
		} else if (line[1] == '\0' && (line[0] == 'n' || line[0] == 'N')) {
			free(line);
			goto done;
		} else {
			free(line);
			goto ynagain;
		}

newprimary:
		tpart = NULL;
		interactive_select_local_token(&tpart);
		if (tpart == NULL)
			goto done;
		tconfig = ebox_tpl_config_alloc(EBOX_PRIMARY);
		ebox_tpl_config_add_part(tconfig, tpart);

		ntpl = ebox_tpl_clone(ebox_tpl(ebox));
		ebox_tpl_add_config(ntpl, tconfig);

		error = ebox_create(ntpl, key, keylen, NULL, 0, &nebox);
		if (error)
			errfx(EXIT_ERROR, error, "ebox_create failed");
		sshbuf_reset(buf);
		error = sshbuf_put_ebox(buf, nebox);
		if (error)
			errfx(EXIT_ERROR, error, "sshbuf_put_ebox failed");

		b64 = sshbuf_dtob64_string(buf, 0);

		json_object_object_add(obj, "ebox",
		    json_object_new_string(b64));

		rc = crypt_token_json_set(cd, 1,
		    json_object_to_json_string(obj));
		if (rc < 0) {
			errfx(EXIT_ERROR, lukserrf("crypt_token_json_set", rc),
			    "failed to set metadata on device '%s'", devname);
		}

		free(b64);
		ebox_tpl_free(ntpl);
	}

done:
	json_object_put(obj);
	ebox_free(ebox);
	sshbuf_free(buf);
	crypt_free(cd);
}

static void
cmd_format(const char *devname)
{
	struct crypt_device *cd;
	struct crypt_params_luks2 params;
	int rc;
	uint8_t *key;
	size_t keylen;
	errf_t *error;
	struct ebox *ebox;
	struct sshbuf *buf;
	char *b64;
	json_object *obj;

	if (lukstpl == NULL) {
		warnx("-t tpl argument is required");
		usage();
	}

	rc = crypt_init(&cd, devname);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_init", rc), "failed to "
		    "open device '%s'", devname);
	}

	bzero(&params, sizeof (params));
	params.sector_size = luks_sectorsz;

	key = calloc_conceal(1, 32);
	keylen = 32;

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);
	arc4random_buf(key, keylen);

	error = ebox_create(lukstpl, key, keylen, NULL, 0, &ebox);
	if (error)
		errfx(EXIT_ERROR, error, "ebox_create failed");
	buf = sshbuf_new();
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");
	error = sshbuf_put_ebox(buf, ebox);
	if (error)
		errfx(EXIT_ERROR, error, "sshbuf_put_ebox failed");

	b64 = sshbuf_dtob64_string(buf, 0);

	rc = crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL,
	    (char *)key, keylen, &params);
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_format", rc), "failed to "
		    "format device '%s'", devname);
	}

	obj = json_object_new_object();
	json_object_object_add(obj, "type", json_object_new_string("ebox"));
	json_object_object_add(obj, "keyslots", json_object_new_array());
	json_object_object_add(obj, "ebox", json_object_new_string(b64));

	rc = crypt_token_json_set(cd, 1, json_object_to_json_string(obj));
	if (rc < 0) {
		errfx(EXIT_ERROR, lukserrf("crypt_token_json_set", rc),
		    "failed to set metadata on device '%s'", devname);
	}

	json_object_put(obj);

	crypt_free(cd);
}

static void
usage(void)
{
	const struct ebox_tpl_path_ent *tpe;
	char *dpath;

	fprintf(stderr,
	    "usage: pivy-luks [-d] [-t tplname] operation device\n"
	    "Options:\n"
	    "  -d                                    Debug mode\n"
	    "  -t tplname                            Template name or path\n"
	    "  -s bytes                              Set LUKS sector size (for format)\n"
	    "\n"
	    "Available operations:\n"
	    "  unlock <device> <mapper name>         Unlock/activate a LUKS device\n"
	    "  rekey <device>                        Update LUKS metadata to new template\n"
	    "  format <device>                       Set up a new LUKS device\n");
	fprintf(stderr, "\nTemplates are stored in:\n");
	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		dpath = compose_path(tpe->tpe_segs, "*");
		fprintf(stderr, "  * %s\n", dpath);
		free(dpath);
		tpe = tpe->tpe_next;
	}
	fprintf(stderr, "(manage them using the `pivy-box' tool)\n");
	exit(EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	const char *optstring = "t:ds:";
	const char *tpl = NULL;
	unsigned long int parsed;
	char *p;

	qa_term_setup();
	bunyan_init();
	bunyan_set_name("pivy-luks");
	parse_tpl_path_env();

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(BNY_TRACE);
			break;
		case 't':
			tpl = optarg;
			break;
		case 's':
			errno = 0;
			parsed = strtoul(optarg, &p, 0);
			if (errno != 0 || *p != '\0') {
				errx(EXIT_USAGE,
				    "invalid argument for -s: '%s'", optarg);
			}
			luks_sectorsz = parsed;
			break;
		default:
			usage();
		}
	}

	if (optind >= argc) {
		warnx("operation required");
		usage();
	}
	const char *op = argv[optind++];
	if (optind >= argc) {
		warnx("device required");
		usage();
	}
	const char *device = argv[optind++];

	if (tpl != NULL)
		lukstpl = read_tpl_file(tpl);

	if (strcmp(op, "format") == 0) {
		if (optind < argc) {
			warnx("too many arguments");
			usage();
		}
		cmd_format(device);
	} else if (strcmp(op, "unlock") == 0) {
		if (optind >= argc) {
			warnx("mapper device name required");
			usage();
		}
		const char *mapperdev = argv[optind++];
		if (optind < argc) {
			warnx("too many arguments");
			usage();
		}
		cmd_unlock(device, mapperdev);
	} else if (strcmp(op, "rekey") == 0) {
		if (optind < argc) {
			warnx("too many arguments");
			usage();
		}
		cmd_rekey(device);
	} else {
		warnx("unknown operation '%s'", op);
		usage();
	}

	return (0);
}

void
cleanup_exit(int i)
{
	exit(i);
}
