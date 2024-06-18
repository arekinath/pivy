/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent Inc
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
#include <dirent.h>
#include <ctype.h>

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
#include "debug.h"
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

#include "tlv.h"
#include "errf.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include "ebox-cmd.h"

static boolean_t ebox_raw_in = B_FALSE;
static boolean_t ebox_raw_out = B_FALSE;
static boolean_t ebox_interactive = B_FALSE;
static struct ebox_tpl *ebox_stpl;
static size_t ebox_keylen = 32;

static errf_t *
parse_hex(const char *str, uint8_t **out, size_t *outlen)
{
	const size_t len = strlen(str);
	uint8_t *data = calloc(1, len / 2 + 1);
	size_t idx = 0;
	size_t shift = 4;
	size_t i;
	for (i = 0; i < len; ++i) {
		const char c = str[i];
		boolean_t skip = B_FALSE;
		if (c >= '0' && c <= '9') {
			data[idx] |= (c - '0') << shift;
		} else if (c >= 'a' && c <= 'f') {
			data[idx] |= (c - 'a' + 0xa) << shift;
		} else if (c >= 'A' && c <= 'F') {
			data[idx] |= (c - 'A' + 0xA) << shift;
		} else if (c == ':' || c == ' ' || c == '\t' ||
		    c == '\n' || c == '\r') {
			skip = B_TRUE;
		} else {
			free(data);
			return (errf("HexParseError", NULL,
			    "invalid hex digit: '%c'", c));
		}
		if (skip == B_FALSE) {
			if (shift == 4) {
				shift = 0;
			} else if (shift == 0) {
				++idx;
				shift = 4;
			}
		}
	}
	if (shift == 0) {
		free(data);
		return (errf("HexParseError", NULL,
		    "odd number of digits (incomplete)"));
	}
	*outlen = idx;
	*out = data;
	return (ERRF_OK);
}


static errf_t *
parse_keywords_part(struct ebox_tpl_config *config, int argc, char *argv[],
    uint *idxp)
{
	uint i = *idxp;
	struct ebox_tpl_part *part = NULL;
	uint8_t *guid = NULL;
	struct sshkey *pubkey = NULL;
	struct sshkey *cak = NULL;
	const char *name = NULL;
	size_t guidlen;
	errf_t *error = NULL;
	int rc;
	char *p;
	enum piv_slotid slotid = PIV_SLOT_KEY_MGMT;
	struct piv_token *token;
	struct piv_slot *slot;

	for (; i < argc; ++i) {
		if (strcmp(argv[i], "part") == 0 ||
		    strcmp(argv[i], "primary") == 0 ||
		    strcmp(argv[i], "recovery") == 0 ||
		    strcmp(argv[i], "add-primary") == 0 ||
		    strcmp(argv[i], "remove-primary") == 0 ||
		    strcmp(argv[i], "add-recovery") == 0 ||
		    strcmp(argv[i], "remove-recovery") == 0 ||
		    strcmp(argv[i], "require") == 0) {
			--i;
			break;
		}
		if (strcmp(argv[i], "guid") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'guid' keyword requires argument");
				goto out;
			}
			error = parse_hex(argv[i], &guid, &guidlen);
			if (error) {
				error = errf("SyntaxError", error,
				    "error parsing argument to 'guid' keyword");
				goto out;
			}
			if (guidlen != GUID_LEN) {
				error = errf("SyntaxError", errf("LengthError",
				    NULL, "guid is not the correct length: %u",
				    guidlen), "error parsing argument to "
				    "'guid' keyword");
				goto out;
			}
		} else if (strcmp(argv[i], "name") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'name' keyword requires argument");
				goto out;
			}
			name = argv[i];
		} else if (strcmp(argv[i], "slot") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'slot' keyword requires argument");
				goto out;
			}
			error = piv_slotid_from_string(argv[i], &slotid);
			if (error != ERRF_OK) {
				error = errf("SyntaxError", error,
				    "error parsing argument to 'slot' "
				    "keyword: '%s'", argv[i]);
				goto out;
			}
		} else if (strcmp(argv[i], "key") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'key' keyword requires argument");
				goto out;
			}
			pubkey = sshkey_new(KEY_ECDSA);
			if (pubkey == NULL) {
				error = ERRF_NOMEM;
				goto out;
			}
			p = argv[i];
			rc = sshkey_read(pubkey, &p);
			if (rc) {
				error = errf("SyntaxError", ssherrf(
				    "sshkey_read", rc), "error parsing "
				    "argument to 'key' keyword");
				goto out;
			}
			if (*p != '\0') {
				error = errf("SyntaxError", NULL,
				    "argument to 'key' keyword has trailing "
				    "garbage");
				goto out;
			}
		} else if (strcmp(argv[i], "cak") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'cak' keyword requires argument");
				goto out;
			}
			cak = sshkey_new(KEY_UNSPEC);
			if (cak == NULL) {
				error = ERRF_NOMEM;
				goto out;
			}
			p = argv[i];
			rc = sshkey_read(cak, &p);
			if (rc) {
				error = errf("SyntaxError", ssherrf(
				    "sshkey_read", rc), "error parsing "
				    "argument to 'cak' keyword");
				goto out;
			}
			if (*p != '\0') {
				error = errf("SyntaxError", NULL,
				    "argument to 'cak' keyword has trailing "
				    "garbage");
				goto out;
			}
		} else if (strcmp(argv[i], "local-guid") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'local-guid' keyword requires argument");
				goto out;
			}
			error = parse_hex(argv[i], &guid, &guidlen);
			if (error) {
				error = errf("SyntaxError", error,
				    "error parsing argument to 'local-guid' "
				    "keyword");
				goto out;
			}
			if (guidlen > GUID_LEN) {
				error = errf("SyntaxError", errf("LengthError",
				    NULL, "guid is too long: %u bytes",
				    guidlen), "error parsing argument to "
				    "'local-guid' keyword");
				goto out;
			}
			if (ebox_ctx == NULL) {
				ebox_ctx = piv_open();
				VERIFY(ebox_ctx != NULL);
				error = piv_establish_context(ebox_ctx,
				    SCARD_SCOPE_SYSTEM);
				if (error &&
				    errf_caused_by(error, "ServiceError")) {
					errf_free(error);
				} else if (error) {
					errfx(EXIT_ERROR, error,
					    "failed to initialise libpcsc");
				}
			}
			error = piv_find(ebox_ctx, guid, guidlen, &token);
			if (error) {
				error = errf("LocalGUIDError", error,
				    "failed to resolve local-guid argument "
				    "'%s'", argv[i]);
				goto out;
			}
			if ((error = piv_txn_begin(token)))
				goto out;
			if ((error = piv_select(token)))
				goto out;
			free(guid);
			guid = malloc(GUID_LEN);
			bcopy(piv_token_guid(token), guid, GUID_LEN);
			guidlen = GUID_LEN;
			error = piv_read_cert(token, PIV_SLOT_CARD_AUTH);
			if (error == ERRF_OK) {
				slot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
				rc = sshkey_demote(piv_slot_pubkey(slot),
				    &cak);
				if (rc) {
					error = ssherrf("sshkey_demote", rc);
					goto out;
				}
			}
			errf_free(error);
			if ((error = piv_read_cert(token, slotid)))
				goto out;
			slot = piv_get_slot(token, slotid);
			rc = sshkey_demote(piv_slot_pubkey(slot), &pubkey);
			if (rc) {
				error = ssherrf("sshkey_demote", rc);
				goto out;
			}
			piv_txn_end(token);
			piv_release(token);
		} else {
			error = errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]);
			goto out;
		}
	}

	if (guid == NULL) {
		error = errf("SyntaxError", NULL,
		    "configuration part missing required 'guid' keyword");
		goto out;
	}

	if (pubkey == NULL) {
		error = errf("SyntaxError", NULL,
		    "configuration part missing required 'key' keyword");
		goto out;
	}

	part = ebox_tpl_part_alloc(guid, guidlen, slotid, pubkey);
	if (part == NULL)
		return (ERRF_NOMEM);
	ebox_tpl_config_add_part(config, part);

	if (name != NULL)
		ebox_tpl_part_set_name(part, name);
	if (cak != NULL)
		ebox_tpl_part_set_cak(part, cak);

out:
	*idxp = i;
	sshkey_free(pubkey);
	sshkey_free(cak);
	free(guid);
	return (error);
}

static errf_t *
parse_keywords_primary(struct ebox_tpl_config *config, int argc, char *argv[],
    uint *idxp)
{
	uint i = *idxp;
	errf_t *error = NULL;

	for (; i < argc; ++i) {
		if (strcmp(argv[i], "primary") == 0 ||
		    strcmp(argv[i], "recovery") == 0 ||
		    strcmp(argv[i], "add-primary") == 0 ||
		    strcmp(argv[i], "remove-primary") == 0 ||
		    strcmp(argv[i], "add-recovery") == 0 ||
		    strcmp(argv[i], "remove-recovery") == 0) {
			--i;
			break;
		}
		if (strcmp(argv[i], "part") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "unexpected end of arguments after 'part'"
				    " keyword");
				goto out;
			}
		}
		error = parse_keywords_part(config, argc, argv, &i);
		if (error)
			goto out;
	}

out:
	*idxp = i;
	return (error);
}

static errf_t *
parse_keywords_recovery(struct ebox_tpl_config *config, int argc, char *argv[],
    uint *idxp)
{
	uint i = *idxp;
	errf_t *error = NULL;
	unsigned long int parsed;
	char *p;

	for (; i < argc; ++i) {
		if (strcmp(argv[i], "primary") == 0 ||
		    strcmp(argv[i], "recovery") == 0 ||
		    strcmp(argv[i], "add-primary") == 0 ||
		    strcmp(argv[i], "remove-primary") == 0 ||
		    strcmp(argv[i], "add-recovery") == 0 ||
		    strcmp(argv[i], "remove-recovery") == 0) {
			--i;
			break;
		}
		if (strcmp(argv[i], "require") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'require' keyword requires argument");
				goto out;
			}
			errno = 0;
			parsed = strtoul(argv[i], &p, 0);
			if (errno != 0 || *p != '\0') {
				error = errf("SyntaxError",
				    errfno("strtoul", errno, NULL),
				    "error parsing argument to 'require' "
				    "keyword: '%s'", argv[i]);
				goto out;
			}
			error = ebox_tpl_config_set_n(config, parsed);
			if (error) {
				error = errf("SyntaxError", error,
				    "error applying argument to 'require' "
				    "keyword: '%s'", argv[i]);
				goto out;
			}

		} else if (strcmp(argv[i], "part") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'part' keyword requires arguments");
				goto out;
			}
			error = parse_keywords_part(config, argc, argv, &i);
			if (error)
				goto out;

		} else {
			return (errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]));
		}
	}

out:
	*idxp = i;
	return (error);
}

static void
interactive_edit_tpl_part(struct ebox_tpl *tpl,
    struct ebox_tpl_config *config, struct ebox_tpl_part *part)
{
	struct question *q;
	struct answer *a;
	char *guidhex;
	int rc;
	struct sshbuf *buf;
	struct sshkey *key;
	char *line, *p;
	errf_t *error;

	buf = sshbuf_new();
	if (buf == NULL)
		err(EXIT_ERROR, "memory allocation failed");

	q = calloc(1, sizeof (struct question));
	if (q == NULL)
		err(EXIT_ERROR, "memory allocation failed");
	a = (struct answer *)ebox_tpl_part_private(part);
	if (a == NULL)
		err(EXIT_ERROR, "memory allocation failed");
	question_printf(q, "-- Editing part %c --\n", a->a_key);

	question_printf(q, "Read-only attributes:\n");
	guidhex = buf_to_hex(ebox_tpl_part_guid(part), GUID_LEN, B_FALSE);
	question_printf(q, "  GUID: %s\n", guidhex);
	free(guidhex);
	question_printf(q, "  Slot: %02X\n", ebox_tpl_part_slot(part));
	if ((rc = sshkey_format_text(ebox_tpl_part_pubkey(part), buf))) {
		errfx(EXIT_ERROR, ssherrf("sshkey_format_text", rc),
		    "failed to write part public key");
	}
	if ((rc = sshbuf_put_u8(buf, '\0'))) {
		errfx(EXIT_ERROR, ssherrf("sshbuf_put_u8", rc),
		    "failed to write part public key (null)");
	}
	question_printf(q, "  Key: %s\n", (char *)sshbuf_ptr(buf));
	sshbuf_reset(buf);

	question_printf(q, "\nSelect an attribute to change:");

	a = make_answer('n', "Name: %s", ebox_tpl_part_name(part));
	add_answer(q, a);
	key = ebox_tpl_part_cak(part);
	if (key != NULL) {
		if ((rc = sshkey_format_text(key, buf))) {
			errfx(EXIT_ERROR, ssherrf("sshkey_format_text", rc),
			    "failed to write part public key");
		}
		if ((rc = sshbuf_put_u8(buf, '\0'))) {
			errfx(EXIT_ERROR, ssherrf("sshbuf_put_u8", rc),
			    "failed to write part public key (null)");
		}
		a = make_answer('c', "Card Auth Key: %s",
		    (char *)sshbuf_ptr(buf));
		sshbuf_reset(buf);
	} else {
		a = make_answer('c', "Card Auth Key: (none set)");
	}
	add_answer(q, a);

	a = make_answer('x', "finish and return");
	add_command(q, a);

again:
	question_prompt(q, &a);
	switch (a->a_key) {
	case 'n':
		line = readline("Name for part? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		ebox_tpl_part_set_name(part, line);
		a->a_used = 0;
		answer_printf(a, "Name: %s", line);
		free(line);
		goto again;
	case 'c':
		line = readline("Card auth key? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		key = sshkey_new(KEY_UNSPEC);
		if (key == NULL)
			err(EXIT_ERROR, "failed to allocate memory");
		p = line;
		rc = sshkey_read(key, &p);
		if (rc) {
			error = ssherrf("sshkey_read", rc);
			warnfx(error, "Invalid card auth key");
			errf_free(error);
			free(line);
			goto again;
		}
		free(line);
		ebox_tpl_part_set_cak(part, key);
		a->a_used = 0;
		if ((rc = sshkey_format_text(key, buf))) {
			errfx(EXIT_ERROR, ssherrf("sshkey_format_text", rc),
			    "failed to write part public key");
		}
		if ((rc = sshbuf_put_u8(buf, '\0'))) {
			errfx(EXIT_ERROR, ssherrf("sshbuf_put_u8", rc),
			    "failed to write part public key (null)");
		}
		answer_printf(a, "Card Auth Key: %s", (char *)sshbuf_ptr(buf));
		sshbuf_reset(buf);
		sshkey_free(key);
		goto again;
	case 'x':
		goto out;
	}
	goto again;
out:
	question_free(q);
}

static void
interactive_edit_tpl_config(struct ebox_tpl *tpl,
    struct ebox_tpl_config *config)
{
	struct question *q, *q2;
	struct answer *a;
	struct ebox_tpl_part *part;
	char *line, *p;
	char k = '0';
	unsigned long int parsed;
	enum piv_slotid slotid;
	errf_t *error;
	uint8_t *guid;
	size_t guidlen;
	struct sshkey *key;
	int rc;

	q = calloc(1, sizeof (struct question));
	a = (struct answer *)ebox_tpl_config_private(config);
	switch (ebox_tpl_config_type(config)) {
	case EBOX_PRIMARY:
		question_printf(q, "-- Editing primary config %c --\n",
		    a->a_key);
		break;
	case EBOX_RECOVERY:
		question_printf(q, "-- Editing recovery config %c --\n",
		    a->a_key);
		a = calloc(1, sizeof (struct answer));
		a->a_key = 'n';
		answer_printf(a, "%u parts required to recover data (change)",
		    ebox_tpl_config_n(config));
		add_command(q, a);
		break;
	}
	question_printf(q, "Select a part to edit:");
	part = NULL;
	while ((part = ebox_tpl_config_next_part(config, part)) != NULL) {
		a = ebox_tpl_part_alloc_private(part, sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = part;
		make_answer_text_for_part(part, a);
		add_answer(q, a);
	}

	a = make_answer('+', "add new part/device");
	add_command(q, a);
	a = make_answer('&', "add new part based on local device");
	add_command(q, a);
	a = make_answer('-', "remove a part");
	add_command(q, a);
	a = make_answer('x', "finish and return");
	add_command(q, a);

again:
	question_prompt(q, &a);
	switch (a->a_key) {
	case '&':
		interactive_select_local_token(&part);
		if (part == NULL)
			goto again;
		ebox_tpl_config_add_part(config, part);

		a = ebox_tpl_part_alloc_private(part, sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = part;

		interactive_edit_tpl_part(tpl, config, part);

		make_answer_text_for_part(part, a);
		add_answer(q, a);

		goto again;
	case '+':
		line = readline("GUID (in hex)? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		error = parse_hex(line, &guid, &guidlen);
		if (error) {
			warnfx(error, "Invalid GUID");
			errf_free(error);
			free(line);
			goto again;
		}
		if (guidlen != GUID_LEN) {
			fprintf(stderr, "Invalid GUID: not correct length\n");
			free(line);
			goto again;
		}
		line = readline("Slot ID (hex or name)? [key-mgmt] ");
		if (line == NULL)
			exit(EXIT_ERROR);
		if (line[0] == '\0') {
			slotid = PIV_SLOT_KEY_MGMT;
		} else {
			error = piv_slotid_from_string(line, &slotid);
			if (error != ERRF_OK) {
				warnfx(error, "error parsing '%s' as slotid",
				    line);
				errf_free(error);
				free(line);
				goto again;
			}
		}
		free(line);
		line = readline("Key? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		key = sshkey_new(KEY_ECDSA);
		if (key == NULL)
			err(EXIT_ERROR, "failed to allocate memory");
		p = line;
		rc = sshkey_read(key, &p);
		if (rc) {
			error = ssherrf("sshkey_read", rc);
			warnfx(error, "Invalid public key");
			errf_free(error);
			free(line);
			goto again;
		}
		free(line);

		part = ebox_tpl_part_alloc(guid, guidlen, slotid, key);
		if (part == NULL)
			err(EXIT_ERROR, "failed to allocate memory");
		sshkey_free(key);
		free(guid);
		ebox_tpl_config_add_part(config, part);

		a = ebox_tpl_part_alloc_private(part, sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = part;

		interactive_edit_tpl_part(tpl, config, part);

		make_answer_text_for_part(part, a);
		add_answer(q, a);

		goto again;
	case '-':
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "Remove which part?");
		q2->q_ans = q->q_ans;
		q2->q_lastans = q->q_lastans;
		a = make_answer('x', "cancel");
		add_command(q2, a);

		question_prompt(q2, &a);
		if (a->a_key != 'x') {
			remove_answer(q, a);
			if (k == a->a_key)
				--k;
			part = (struct ebox_tpl_part *)a->a_priv;
			ebox_tpl_config_remove_part(config, part);
			ebox_tpl_part_free(part);
		}
		q2->q_ans = (q2->q_lastans = NULL);
		question_free(q2);
		goto again;
	case 'n':
		line = readline("Number of parts required? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		errno = 0;
		parsed = strtoul(line, &p, 0);
		if (errno != 0 || *p != '\0') {
			free(line);
			fprintf(stderr, "Failed to interpret response as "
			    "a valid number: %s\n", strerror(errno));
			goto again;
		}
		error = ebox_tpl_config_set_n(config, parsed);
		if (error) {
			warnfx(error, "Invalid value for N");
			errf_free(error);
		}
		free(line);
		a->a_used = 0;
		answer_printf(a, "%u parts required to recover data (change)",
		    ebox_tpl_config_n(config));
		goto again;
	case 'x':
		goto out;
	}
	part = (struct ebox_tpl_part *)a->a_priv;
	interactive_edit_tpl_part(tpl, config, part);
	make_answer_text_for_part(part, a);
	goto again;
out:
	part = NULL;
	while ((part = ebox_tpl_config_next_part(config, part)) != NULL) {
		a = (struct answer *)ebox_tpl_part_private(part);
		remove_answer(q, a);
		ebox_tpl_part_free_private(part);
	}
	question_free(q);
}

static void
interactive_edit_tpl(struct ebox_tpl *tpl)
{
	struct question *q, *q2;
	struct answer *a;
	struct ebox_tpl_config *config;
	char k = '0', k2 = '0';
	struct ebox_tpl *otpl;
	errf_t *err;

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Editing template --\n");
	question_printf(q, "Select a configuration to edit:");
	config = NULL;
	while ((config = ebox_tpl_next_config(tpl, config)) != NULL) {
		a = ebox_tpl_config_alloc_private(config,
		    sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = config;
		make_answer_text_for_config(config, a);
		add_answer(q, a);
	}

	a = make_answer('+', "add new configuration");
	add_command(q, a);
	a = make_answer('&', "import configuration from another template");
	add_command(q, a);
	a = make_answer('-', "remove a configuration");
	add_command(q, a);
	a = make_answer('w', "write and exit");
	add_command(q, a);

again:
	question_prompt(q, &a);
	switch (a->a_key) {
	case '+':
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "Add what type of configuration?");
		a = make_answer('p', "primary (single device)");
		add_answer(q2, a);
		a = make_answer('r', "recovery (multi-device, N out of M)");
		add_answer(q2, a);

		a = make_answer('x', "cancel");
		add_command(q2, a);

		question_prompt(q2, &a);
		if (a->a_key == 'p') {
			config = ebox_tpl_config_alloc(EBOX_PRIMARY);
		} else if (a->a_key == 'r') {
			config = ebox_tpl_config_alloc(EBOX_RECOVERY);
		} else {
			question_free(q2);
			goto again;
		}
		ebox_tpl_add_config(tpl, config);

		a = ebox_tpl_config_alloc_private(config,
		    sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = config;

		interactive_edit_tpl_config(tpl, config);

		make_answer_text_for_config(config, a);
		add_answer(q, a);

		question_free(q2);
		goto again;
	case '&':
		err = interactive_select_tpl(&otpl);
		if (err != ERRF_OK) {
			errf_free(err);
			goto again;
		}
		k2 = '0';
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "-- Import configuration --\n");
		question_printf(q2, "Select a configuration to import:");
		config = NULL;
		while ((config = ebox_tpl_next_config(otpl, config)) != NULL) {
			a = calloc(1, sizeof (struct answer));
			a->a_key = ++k2;
			a->a_priv = config;
			make_answer_text_for_config(config, a);
			add_answer(q2, a);
		}
		a = make_answer('x', "cancel");
		add_command(q2, a);
		question_prompt(q2, &a);
		if (a->a_key == 'x') {
			for (a = q2->q_ans; a != NULL; a = a->a_next)
				a->a_priv = NULL;
			question_free(q2);
			ebox_tpl_free(otpl);
			goto again;
		}
		config = a->a_priv;
		for (a = q2->q_ans; a != NULL; a = a->a_next)
			a->a_priv = NULL;
		question_free(q2);
		ebox_tpl_remove_config(otpl, config);
		ebox_tpl_add_config(tpl, config);
		ebox_tpl_free(otpl);

		a = ebox_tpl_config_alloc_private(config,
		    sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = config;

		make_answer_text_for_config(config, a);
		add_answer(q, a);

		goto again;
	case '-':
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "Remove which configuration?");
		q2->q_ans = q->q_ans;
		q2->q_lastans = q->q_lastans;
		a = make_answer('x', "cancel");
		add_command(q2, a);

		question_prompt(q2, &a);
		if (a->a_key != 'x') {
			remove_answer(q, a);
			if (k == a->a_key)
				--k;
			config = (struct ebox_tpl_config *)a->a_priv;
			ebox_tpl_remove_config(tpl, config);
			ebox_tpl_config_free(config);
		}
		q2->q_ans = (q2->q_lastans = NULL);
		question_free(q2);
		goto again;
	case 'w':
		goto write;
	}
	config = (struct ebox_tpl_config *)a->a_priv;
	interactive_edit_tpl_config(tpl, config);
	make_answer_text_for_config(config, a);
	goto again;
write:
	return;
}

static errf_t *
cmd_tpl_create(const char *tplfile, int argc, char *argv[])
{
	uint i;
	size_t len;
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config = NULL;
	errf_t *error = NULL;
	struct sshbuf *buf;
	FILE *file;
	char *dirpath;

	tpl = ebox_tpl_alloc();

	for (i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "primary") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'primary' keyword requires arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_PRIMARY);
			ebox_tpl_add_config(tpl, config);
			error = parse_keywords_primary(config, argc, argv, &i);
			if (error)
				return (error);
		} else if (strcmp(argv[i], "recovery") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'recovery' keyword requires arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_RECOVERY);
			ebox_tpl_add_config(tpl, config);
			error = parse_keywords_recovery(config, argc, argv, &i);
			if (error)
				return (error);
		} else {
			return (errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]));
		}
	}

	if (ebox_interactive) {
		interactive_edit_tpl(tpl);
	}

	buf = sshbuf_new();
	error = sshbuf_put_ebox_tpl(buf, tpl);
	if (error)
		return (error);

	file = fopen(tplfile, "w");
	if (file == NULL && errno == ENOENT) {
		dirpath = strdup(tplfile);
		len = strlen(dirpath);
		for (i = 1; i < len; ++i) {
			if (dirpath[i] != '/')
				continue;
			dirpath[i] = '\0';
			if (mkdir(dirpath, 0755)) {
				if (errno != EEXIST) {
					return (errfno("mkdir", errno,
					    "creating directory '%s'",
					    dirpath));
				}
			}
			dirpath[i] = '/';
		}
		free(dirpath);
		file = fopen(tplfile, "w");
	}
	if (file == NULL) {
		return (errfno("fopen", errno, "opening template file '%s' "
		    "for writing", tplfile));
	}
	printwrap(file, sshbuf_dtob64_string(buf, 0), BASE64_LINE_LEN);
	fclose(file);

out:
	ebox_tpl_free(tpl);
	return (error);
}

static char *
strip_lines(const char *buf)
{
	const size_t len = strlen(buf);
	char *out = malloc(len);
	const char *line = buf, *l;
	const char *eol;
	size_t off = 0;

	*out = '\0';

	while (*line != '\0') {
		eol = strchr(line, '\n');
		if (eol == NULL) {
			off = strlcat(out, line, len);
			if (off >= len) {
				free(out);
				return (NULL);
			}
			break;
		}
		const size_t llen = eol - line;
		for (l = line; isspace(*l); )
			++l;
		if (strncasecmp(l, "-- end ", 7) == 0 &&
		    eol[-1] == '-' && eol[-2] == '-') {
			/* Ignore everything after an end banner */
			break;
		}
		if (strncasecmp(l, "-- begin ", 9) == 0 &&
		    eol[-1] == '-' && eol[-2] == '-') {
			/* Ignore everything before a begin banner */
			off = 0;
			*out = '\0';
			line = eol + 1;
			continue;
		}
		if (strncmp(l, "--", 2) == 0) {
			/* Ignore any other lines starting with -- */
			line = eol + 1;
			continue;
		}
		if (off + llen >= len) {
			free(out);
			return (NULL);
		}
		bcopy(line, &out[off], llen);
		off += llen;
		out[off] = '\0';
		line = eol + 1;
	}
	return (out);
}

static struct sshbuf *
read_file_b64(size_t limit, FILE *file)
{
	char *buf = malloc(limit + 1);
	struct sshbuf *sbuf;
	size_t n;
	int rc;

	n = fread(buf, 1, limit, file);
	if (ferror(file))
		err(EXIT_USAGE, "error reading input");
	if (!feof(file))
		errx(EXIT_USAGE, "input too long (max %zu bytes)", limit);
	if (n > limit)
		errx(EXIT_USAGE, "input too long (max %zu bytes)", limit);

	sbuf = sshbuf_new();
	if (sbuf == NULL)
		err(EXIT_ERROR, "failed to allocate buffer");

	if (!ebox_raw_in) {
		buf[n] = '\0';
		rc = sshbuf_b64tod(sbuf, strip_lines(buf));
		if (rc) {
			errf_t *error = ssherrf("sshbuf_b64tod", rc);
			errfx(EXIT_ERROR, error, "error parsing input as "
			    "base64");
		}
	} else {
		rc = sshbuf_put(sbuf, buf, n);
		if (rc) {
			errf_t *error = ssherrf("sshbuf_put", rc);
			errfx(EXIT_ERROR, error, "error reading input");
		}
	}
	free(buf);
	return (sbuf);
}

static struct sshbuf *
read_stdin_b64(size_t limit)
{
	return (read_file_b64(limit, stdin));
}

static errf_t *
cmd_tpl_edit(const char *tplfile, int argc, char *argv[])
{
	uint i;
	size_t len;
	struct ebox_tpl_config *config = NULL, *nconfig;
	errf_t *error = NULL;
	struct sshbuf *buf;
	FILE *file;
	char *dirpath;

	for (i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "add-primary") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'add-primary' keyword requires arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_PRIMARY);
			ebox_tpl_add_config(ebox_stpl, config);
			error = parse_keywords_primary(config, argc, argv, &i);
			if (error)
				return (error);
		} else if (strcmp(argv[i], "add-recovery") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'add-recovery' keyword requires "
				    "arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_RECOVERY);
			ebox_tpl_add_config(ebox_stpl, config);
			error = parse_keywords_recovery(config, argc, argv, &i);
			if (error)
				return (error);
		} else if (strcmp(argv[i], "remove-primary") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'remove-primary' keyword requires "
				    "arguments");
				goto out;
			}
			if (strcmp(argv[i], "all") == 0) {
				nconfig = ebox_tpl_next_config(ebox_stpl, NULL);
				while ((config = nconfig) != NULL) {
					nconfig = ebox_tpl_next_config(
					    ebox_stpl, config);
					if (ebox_tpl_config_type(config) ==
					    EBOX_PRIMARY) {
						ebox_tpl_remove_config(
						    ebox_stpl, config);
						ebox_tpl_config_free(config);
					}
				}
			} else {
				return (errf("SyntaxError", NULL,
				    "unexpected argument to "
				    "remove-primary: '%s'", argv[i]));
			}
		} else if (strcmp(argv[i], "remove-recovery") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'remove-recovery' keyword requires "
				    "arguments");
				goto out;
			}
			if (strcmp(argv[i], "all") == 0) {
				nconfig = ebox_tpl_next_config(ebox_stpl, NULL);
				while ((config = nconfig) != NULL) {
					nconfig = ebox_tpl_next_config(
					    ebox_stpl, config);
					if (ebox_tpl_config_type(config) ==
					    EBOX_RECOVERY) {
						ebox_tpl_remove_config(
						    ebox_stpl, config);
						ebox_tpl_config_free(config);
					}
				}
			} else {
				return (errf("SyntaxError", NULL,
				    "unexpected argument to "
				    "remove-recovery: '%s'", argv[i]));
			}
		} else {
			return (errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]));
		}
	}

	if (ebox_interactive) {
		interactive_edit_tpl(ebox_stpl);
	}

	buf = sshbuf_new();
	error = sshbuf_put_ebox_tpl(buf, ebox_stpl);
	if (error)
		return (error);

	file = fopen(tplfile, "w");
	if (file == NULL && errno == ENOENT) {
		dirpath = strdup(tplfile);
		len = strlen(dirpath);
		for (i = 1; i < len; ++i) {
			if (dirpath[i] != '/')
				continue;
			dirpath[i] = '\0';
			if (mkdir(dirpath, 0755)) {
				if (errno != EEXIST) {
					return (errfno("mkdir", errno,
					    "creating directory '%s'",
					    dirpath));
				}
			}
			dirpath[i] = '/';
		}
		free(dirpath);
		file = fopen(tplfile, "w");
	}
	if (file == NULL) {
		return (errfno("fopen", errno, "opening template file '%s' "
		    "for writing", tplfile));
	}
	printwrap(file, sshbuf_dtob64_string(buf, 0), BASE64_LINE_LEN);
	fclose(file);

out:
	return (error);
}

static void
print_tpl(FILE *stream, const struct ebox_tpl *tpl)
{
	struct ebox_tpl_config *config = NULL;
	int rc;

	fprintf(stream, "-- template --\n");
	fprintf(stream, "version: %u\n", ebox_tpl_version(tpl));

	while ((config = ebox_tpl_next_config(tpl, config))) {
		fprintf(stream, "configuration:\n");
		switch (ebox_tpl_config_type(config)) {
		case EBOX_PRIMARY:
			fprintf(stream, "  type: primary\n");
			break;
		case EBOX_RECOVERY:
			fprintf(stream, "  type: recovery\n");
			fprintf(stream, "  required: %u parts\n",
			    ebox_tpl_config_n(config));
			break;
		}
		struct ebox_tpl_part *part = NULL;
		while ((part = ebox_tpl_config_next_part(config, part))) {
			char *guidhex;
			fprintf(stream, "  part:\n");
			guidhex = buf_to_hex(ebox_tpl_part_guid(part),
			    GUID_LEN, B_FALSE);
			fprintf(stream, "    guid: %s\n", guidhex);
			free(guidhex);
			if (ebox_tpl_part_name(part) != NULL) {
				fprintf(stream, "    name: %s\n",
				    ebox_tpl_part_name(part));
			}
			fprintf(stream, "    slot: %02X\n",
			    ebox_tpl_part_slot(part));
			fprintf(stream, "    key: ");
			rc = sshkey_write(ebox_tpl_part_pubkey(part), stream);
			if (rc != 0) {
				errfx(EXIT_ERROR, ssherrf("sshkey_write", rc),
				    "failed to print pubkey of ebox part");
			}
			fprintf(stream, "\n");
			if (ebox_tpl_part_cak(part) != NULL) {
				fprintf(stream, "    cak: ");
				rc = sshkey_write(ebox_tpl_part_cak(part),
				    stream);
				if (rc != 0) {
					errfx(EXIT_ERROR,
					    ssherrf("sshkey_write", rc),
					    "failed to print cak of ebox part");
				}
				fprintf(stream, "\n");
			}
		}
	}
}

static errf_t *
cmd_tpl_show(int argc, char *argv[])
{
	errf_t *error;

	if (ebox_stpl == NULL) {
		struct sshbuf *sbuf = read_stdin_b64(TPL_MAX_SIZE);
		error = sshbuf_get_ebox_tpl(sbuf, &ebox_stpl);
		if (error) {
			errfx(EXIT_ERROR, error, "failed to parse input as "
			    "a base64-encoded ebox template");
		}
		sshbuf_free(sbuf);
	}

	print_tpl(stderr, ebox_stpl);

	return (NULL);
}

static errf_t *
cmd_tpl_list(int argc, char *argv[])
{
	struct dirent *ent;
	DIR *d;
	char *dpath;
	char *fpath;
	const struct ebox_tpl_path_ent *tpe;
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *c;
	struct answer a;
	errf_t *err = NULL;
	boolean_t success = B_FALSE;

	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		dpath = compose_path(tpe->tpe_segs, "");

		d = opendir(dpath);
		if (d == NULL) {
			errf_free(err);
			err = errfno("opendir", errno, "%s", dpath);
			goto next;
		}

		printf("ebox templates in %s:\n", dpath);

		while ((ent = readdir(d)) != NULL) {
			if (ent->d_name[0] == '.')
				continue;

			fpath = compose_path(tpe->tpe_segs, ent->d_name);
			tpl = read_tpl_file(fpath);

			printf("  %s:\n", ent->d_name);
			c = NULL;
			while ((c = ebox_tpl_next_config(tpl, c)) != NULL) {
				bzero(&a, sizeof (a));
				make_answer_text_for_config(c, &a);
				printf("   * %s\n", a.a_text);
			}

			free(fpath);
		}
		success = B_TRUE;
		printf("\n");

		closedir(d);

		free(dpath);

next:
		tpe = tpe->tpe_next;
	}
	if (success) {
		errf_free(err);
		err = NULL;
	}
	return (err);
}

static errf_t *
cmd_key_generate(int argc, char *argv[])
{
	uint8_t *key;
	struct ebox *ebox;
	errf_t *error;
	struct sshbuf *buf;

	key = calloc_conceal(1, ebox_keylen);
	if (key == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);
	arc4random_buf(key, ebox_keylen);

	error = ebox_create(ebox_stpl, key, ebox_keylen, NULL, 0, &ebox);
	if (error)
		return (error);

	buf = sshbuf_new();
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	error = sshbuf_put_ebox(buf, ebox);
	if (error)
		return (error);

	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64_string(buf, 0), BASE64_LINE_LEN);
	}

	ebox_free(ebox);
	return (ERRF_OK);
}

static errf_t *
cmd_key_lock(int argc, char *argv[])
{
	const uint8_t *key;
	size_t keylen;
	struct ebox *ebox;
	errf_t *error;
	struct sshbuf *kbuf, *buf;

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	kbuf = read_stdin_b64(EBOX_MAX_SIZE);
	key = sshbuf_ptr(kbuf);
	keylen = sshbuf_len(kbuf);

	set_no_dump((void *)key, keylen);

	error = ebox_create(ebox_stpl, key, keylen, NULL, 0, &ebox);
	if (error)
		return (error);

	buf = sshbuf_new();
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	error = sshbuf_put_ebox(buf, ebox);
	if (error)
		return (error);

	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64_string(buf, 0),
		    BASE64_LINE_LEN);
	}

	sshbuf_free(buf);
	sshbuf_free(kbuf);

	ebox_free(ebox);
	return (ERRF_OK);
}

static errf_t *
cmd_key_relock(int argc, char *argv[])
{
	struct ebox *ebox, *nebox;
	errf_t *error;
	struct sshbuf *buf;
	size_t keylen;
	const uint8_t *key;
	const char *fname = NULL;

	if (argc == 1) {
		FILE *file;
		fname = argv[0];
		file = fopen(fname, "r");
		if (file == NULL)
			err(EXIT_USAGE, "failed to open file %s", fname);
		buf = read_file_b64(EBOX_MAX_SIZE, file);
		fclose(file);
	} else if (argc == 0) {
		buf = read_stdin_b64(EBOX_MAX_SIZE);
	} else {
		errx(EXIT_USAGE, "too many arguments for pivy-box "
		    "key relock");
	}

	error = sshbuf_get_ebox(buf, &ebox);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox");
	}

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	error = interactive_unlock_ebox(ebox, fname);
	if (error)
		return (error);

	key = ebox_key(ebox, &keylen);

	error = ebox_create(ebox_stpl, key, keylen, NULL, 0, &nebox);
	if (error)
		return (error);

	sshbuf_reset(buf);

	error = sshbuf_put_ebox(buf, nebox);
	if (error)
		return (error);

	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64_string(buf, 0),
		    BASE64_LINE_LEN);
	}

	ebox_free(ebox);
	ebox_free(nebox);
	return (ERRF_OK);
}

static errf_t *
cmd_key_info(int argc, char *argv[])
{
	struct sshbuf *buf;
	struct ebox *ebox;
	struct ebox_tpl *tpl;
	struct ebox_config *config = NULL;
	errf_t *error;
	const char *fname;
	uint i;

	if (argc == 1) {
		FILE *file;
		fname = argv[0];
		file = fopen(fname, "r");
		if (file == NULL)
			err(EXIT_USAGE, "failed to open file %s", fname);
		buf = read_file_b64(EBOX_MAX_SIZE, file);
		fclose(file);
	} else if (argc == 0) {
		buf = read_stdin_b64(EBOX_MAX_SIZE);
	} else {
		errx(EXIT_USAGE, "too many arguments for pivy-box "
		    "key info");
	}

	error = sshbuf_get_ebox(buf, &ebox);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox");
	}
	sshbuf_free(buf);

	fprintf(stderr, "-- ebox --\n");
	fprintf(stderr, "version: %u\n", ebox_version(ebox));
	switch (ebox_type(ebox)) {
	case EBOX_KEY:
		fprintf(stderr, "type: key\n");
		break;
	case EBOX_STREAM:
		fprintf(stderr, "type: stream\n");
		break;
	default:
		break;
	}
	fprintf(stderr, "ephemeral keys: %u\n", ebox_ephem_count(ebox));
	for (i = 0; i < ebox_ephem_count(ebox); ++i) {
		const struct sshkey *k = ebox_ephem_pubkey(ebox, i);
		char *fp;
		VERIFY3U(k->type, ==, KEY_ECDSA);
		fp = sshkey_fingerprint(k, SSH_DIGEST_SHA256, SSH_FP_BASE64);
		fprintf(stderr, "  curve %s:\n    fingerprint: %s\n    key: ",
		    sshkey_curve_nid_to_name(k->ecdsa_nid), fp);
		(void)sshkey_write(k, stderr);
		fprintf(stderr, "\n");
		free(fp);
	}
	fprintf(stderr, "recovery cipher: %s\n", ebox_cipher(ebox));

	while ((config = ebox_next_config(ebox, config)) != NULL) {
		size_t len = ebox_config_nonce_len(config);
		if (len > 0)
			fprintf(stderr, "per-config nonce: %zu bytes\n", len);
	}

	tpl = ebox_tpl(ebox);
	print_tpl(stderr, tpl);

	ebox_free(ebox);

	return (ERRF_OK);
}

static errf_t *
cmd_key_unlock(int argc, char *argv[])
{
	struct ebox *ebox;
	errf_t *error;
	struct sshbuf *buf;
	size_t keylen;
	const uint8_t *key;
	char *b64;
	const char *fname = NULL;

	if (argc == 1) {
		FILE *file;
		fname = argv[0];
		file = fopen(fname, "r");
		if (file == NULL)
			err(EXIT_USAGE, "failed to open file %s", fname);
		buf = read_file_b64(EBOX_MAX_SIZE, file);
		fclose(file);
	} else if (argc == 0) {
		buf = read_stdin_b64(EBOX_MAX_SIZE);
	} else {
		errx(EXIT_USAGE, "too many arguments for pivy-box "
		    "key unlock");
	}

	error = sshbuf_get_ebox(buf, &ebox);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox");
	}
	sshbuf_free(buf);

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	error = interactive_unlock_ebox(ebox, fname);
	if (error)
		return (error);

	key = ebox_key(ebox, &keylen);
	buf = sshbuf_from(key, keylen);
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");
	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		b64 = sshbuf_dtob64_string(buf, 0);
		printwrap(stdout, b64, BASE64_LINE_LEN);
		free(b64);
	}
	sshbuf_free(buf);
	ebox_free(ebox);
	return (ERRF_OK);
}

static errf_t *
cmd_stream_encrypt(int argc, char *argv[])
{
	struct ebox_stream *es;
	struct ebox_stream_chunk *esc;
	errf_t *error;
	uint8_t *ibuf;
	struct sshbuf *obuf;
	size_t chunksz, nread, nwrote;
	size_t seq = 0;

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	error = ebox_stream_new(ebox_stpl, &es);
	if (error)
		return (error);
	chunksz = ebox_stream_chunk_size(es);
	ibuf = malloc(chunksz);
	if (ibuf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");
	obuf = sshbuf_new();
	if (obuf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	error = sshbuf_put_ebox_stream(obuf, es);
	if (error)
		return (error);
	while (sshbuf_len(obuf) > 0) {
		nwrote = fwrite(sshbuf_ptr(obuf), 1, sshbuf_len(obuf), stdout);
		sshbuf_consume(obuf, nwrote);
	}
	sshbuf_reset(obuf);

	while (!feof(stdin) && !ferror(stdin)) {
		nread = fread(ibuf, 1, chunksz, stdin);
		if (nread < 1)
			continue;
		error = ebox_stream_chunk_new(es, ibuf, nread, ++seq, &esc);
		if (error)
			return (error);
		error = ebox_stream_encrypt_chunk(esc);
		if (error)
			return (error);
		error = sshbuf_put_ebox_stream_chunk(obuf, esc);
		if (error)
			return (error);
		while (sshbuf_len(obuf) > 0) {
			nwrote = fwrite(sshbuf_ptr(obuf), 1, sshbuf_len(obuf),
			    stdout);
			sshbuf_consume(obuf, nwrote);
		}
		sshbuf_reset(obuf);
		ebox_stream_chunk_free(esc);
	}

	ebox_stream_free(es);
	return (ERRF_OK);
}

static errf_t *
cmd_stream_decrypt(int argc, char *argv[])
{
	struct ebox_stream *es = NULL;
	struct ebox_stream_chunk *esc = NULL;
	struct ebox *ebox;
	errf_t *error;
	uint8_t *buf;
	const uint8_t *data;
	struct sshbuf *ibuf, *nbuf;
	size_t nread, nwrote, poff;
	FILE *file;
	const char *fname = NULL;

	if (argc == 1) {
		fname = argv[0];
		file = fopen(fname, "r");
		if (file == NULL)
			err(EXIT_USAGE, "failed to open file %s", fname);
	} else if (argc == 0) {
		file = stdin;
	} else {
		errx(EXIT_USAGE, "too many arguments for pivy-box "
		    "stream decrypt");
	}

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	buf = malloc(8192);
	VERIFY(buf != NULL);

	ibuf = sshbuf_new();
	VERIFY(ibuf != NULL);

	while (es == NULL) {
		nread = fread(buf, 1, 8192, file);
		if (nread < 1 && ferror(file))
			err(EXIT_ERROR, "failed to read input");
		VERIFY0(sshbuf_put(ibuf, buf, nread));

		poff = sshbuf_offset(ibuf);
		error = sshbuf_get_ebox_stream(ibuf, &es);
		if (errf_caused_by(error, "IncompleteMessageError")) {
			if (feof(file))
				errfx(EXIT_ERROR, error, "input too short");
			VERIFY0(sshbuf_rewind(ibuf, poff));
			errf_free(error);
			continue;
		} else if (error) {
			return (error);
		}
		break;
	}

	if (es == NULL) {
		return (errf("IncompleteInputError", NULL,
		    "input was incomplete"));
	}

	ebox = ebox_stream_ebox(es);

	error = interactive_unlock_ebox(ebox, fname);
	if (error)
		return (error);

	while (1) {
		nread = fread(buf, 1, 8192, file);
		if (nread < 1 && ferror(file))
			err(EXIT_ERROR, "failed to read input");
		else if (nread < 1 && feof(file) && sshbuf_len(ibuf) == 0)
			break;
		VERIFY0(sshbuf_put(ibuf, buf, nread));

		poff = sshbuf_offset(ibuf);
		error = sshbuf_get_ebox_stream_chunk(ibuf, es, &esc);
		if (errf_caused_by(error, "IncompleteMessageError")) {
			if (feof(file))
				errfx(EXIT_ERROR, error, "input too short");
			VERIFY0(sshbuf_rewind(ibuf, poff));
			errf_free(error);
			continue;
		} else if (error) {
			return (error);
		}

		error = ebox_stream_decrypt_chunk(esc);
		if (error)
			return (error);

		data = ebox_stream_chunk_data(esc, &nread);

		nwrote = fwrite(data, 1, nread, stdout);
		if (nwrote < nread)
			err(EXIT_ERROR, "failed to write data");

		ebox_stream_chunk_free(esc);
		esc = NULL;

		if (sshbuf_len(ibuf) > 0) {
			nbuf = sshbuf_new();
			VERIFY(nbuf != NULL);
			VERIFY0(sshbuf_put(nbuf, sshbuf_ptr(ibuf),
			    sshbuf_len(ibuf)));
			sshbuf_free(ibuf);
			ibuf = nbuf;
		}
	}

	ebox_stream_free(es);
	ebox_stream_chunk_free(esc);
	return (ERRF_OK);
}

static void
print_challenge(const struct ebox_challenge *chal)
{
	const char *purpose;
	struct tm tmctime;
	time_t ctime;
	char tbuf[128];
	const uint8_t *words;
	size_t wordlen;

	fprintf(stderr, "-- Challenge --\n");
	switch (ebox_challenge_type(chal)) {
	case CHAL_RECOVERY:
		purpose = "recovery of at-rest encryption keys";
		break;
	case CHAL_VERIFY_AUDIT:
		purpose = "verification of hash-chain audit trail";
		break;
	default:
		exit(1);
	}
	fprintf(stderr, "%-20s   %s\n", "Purpose", purpose);
	fprintf(stderr, "%-20s   %s\n", "Description",
	    ebox_challenge_desc(chal));
	fprintf(stderr, "%-20s   %s\n", "Hostname",
	    ebox_challenge_hostname(chal));

	bzero(&tmctime, sizeof (tmctime));
	ctime = (time_t)ebox_challenge_ctime(chal);
	localtime_r(&ctime, &tmctime);
	strftime(tbuf, sizeof (tbuf), "%Y-%m-%d %H:%M:%S", &tmctime);
	fprintf(stderr, "%-20s   %s (local time)\n", "Generated at", tbuf);

	words = ebox_challenge_words(chal, &wordlen);
	VERIFY3U(wordlen, ==, 4);
	fprintf(stderr, "\n%-20s   %s %s %s %s\n\n", "VERIFICATION WORDS",
	    wordlist[words[0]], wordlist[words[1]],
	    wordlist[words[2]], wordlist[words[3]]);
}

static errf_t *
cmd_challenge_info(int argc, char *argv[])
{
	struct ebox_challenge *chal;
	struct sshbuf *sbuf;
	struct piv_ecdh_box *box;
	errf_t *error;

	sbuf = read_stdin_b64(TPL_MAX_SIZE);
	error = sshbuf_get_piv_box(sbuf, &box);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox challenge");
	}
	sshbuf_free(sbuf);

	error = local_unlock(box, NULL, NULL);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to unlock challenge");
	}

	error = sshbuf_get_ebox_challenge(box, &chal);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse contents of "
		    "challenge box");
	}

	print_challenge(chal);

	return (NULL);
}

static errf_t *
cmd_challenge_respond(int argc, char *argv[])
{
	struct ebox_challenge *chal;
	struct sshbuf *sbuf;
	struct piv_ecdh_box *box;
	errf_t *error;
	char *line;

	sbuf = read_stdin_b64(TPL_MAX_SIZE);
	error = sshbuf_get_piv_box(sbuf, &box);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox challenge");
	}

	error = local_unlock(box, NULL, NULL);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to unlock challenge");
	}

	error = sshbuf_get_ebox_challenge(box, &chal);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse contents of "
		    "challenge box");
	}

	print_challenge(chal);

	fprintf(stderr, "Please check that these verification words match the "
	    "original source via a\nseparate communications channel to the "
	    "one used to transport the challenge\nitself.\n\n");

	line = readline("If these details are correct and you wish to "
	    "respond, type 'YES': ");
	if (line == NULL)
		exit(EXIT_ERROR);
	if (strcmp(line, "YES") != 0)
		exit(EXIT_ERROR);
	free(line);

	box = ebox_challenge_box(chal);
	error = local_unlock(box, NULL, NULL);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to unlock challenge");
	}

	sshbuf_reset(sbuf);
	error = sshbuf_put_ebox_challenge_response(sbuf, chal);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to generate response");
	}

	fprintf(stdout, "-- Begin response --\n");
	printwrap(stdout, sshbuf_dtob64_string(sbuf, 0), BASE64_LINE_LEN);
	fprintf(stdout, "-- End response --\n");

	sshbuf_free(sbuf);

	return (NULL);
}

static void
usage_types(void)
{
	const struct ebox_tpl_path_ent *tpe;
	char *dpath;

	fprintf(stderr,
	    "usage: pivy-box <type> <operation> [options] [tpl]\n"
	    "\n");
	fprintf(stderr,
	    "Creates and manages eboxes, which encrypt data so that it can be\n"
	    "decrypted and authenticated using PIV tokens (or N/M sets of PIV\n"
	    "tokens) supported by pivy.\n"
	    "\n"
	    "Options:\n"
	    "  -b         batch mode, don't talk to terminal\n"
	    "  -r         raw input, don't base64-decode stdin\n"
	    "  -R         raw output, don't base64-encode stdout\n"
	    "  -i         interactive mode (for editing etc)\n"
	    "  -f <path>  full path to tpl file instead of using [tpl] arg\n"
	    "\n");
	fprintf(stderr, "If not using -f, templates are stored in:\n");
	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		dpath = compose_path(tpe->tpe_segs, "");
		fprintf(stderr, "  * %s\n", dpath);
		free(dpath);
		tpe = tpe->tpe_next;
	}
	fprintf(stderr,
	    "pivy-box <type>:\n"
	    "  tpl|template          Manage templates which track a set of\n"
	    "                        devices and N/M config\n"
	    "  key                   Encrypt small amounts of data (up to 10s\n"
	    "                        of bytes)\n"
	    "  stream                Encrypt larger amounts of data which can\n"
	    "                        be streamed (doesn't have to fit in RAM)\n"
	    "  challenge             Respond to recovery challenges issued by\n"
	    "                        other commands\n");
}

static void
usage_tpl(const char *op)
{
	const struct ebox_tpl_path_ent *tpe;
	char *dpath;
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "create") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl create [-i] <tpl> [builder...]\n"
		    "\n"
		    "Creates a new template which can then be used with the\n"
		    "pivy-box key or stream commands. Can be invoked either\n"
		    "with a set of 'builder' arguments to specify the template\n"
		    "or with -i to interactively create it through a menu\n"
		    "interface.\n"
		    "\n"
		    "Options:\n"
		    "  -i         interactive mode\n"
		    "\n"
		    "<builder>:\n"
		    "  primary < ... >        Specifies a primary config\n"
		    "    local-guid <guid>    Generates based on a local device\n"
		    "    name <string>\n"
		    "    guid <guid>\n"
		    "    slot <hex>\n"
		    "    key <'ecdsa-sha2-nistp256 AA...'>       Sets 9d key\n"
		    "    cak <'ecdsa-sha2-nistp256 AA...'>       Sets 9e key\n"
		    "  recovery < ... >       Specifies a recovery config\n"
		    "    require <int>        Set # of parts required\n"
		    "    part < ... >         Specifies a part for the config\n"
		    "      name/guid/slot/key\n");
	} else if (strcmp(op, "edit") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl edit [-i] <tpl> [builder...]\n"
		    "\n"
		    "Makes changes to an existing template.\n"
		    "\n"
		    "Options:\n"
		    "  -i         interactive mode\n"
		    "\n"
		    "<builder>:\n"
		    "  remove-primary all     Remove all primary configs\n"
		    "  remove-recovery all    Remove all recovery configs\n"
		    "  add-primary < ... >    Add a new primary config\n"
		    "    local-guid <guid>    Generates based on a local device\n"
		    "    name <string>\n"
		    "    guid <guid>\n"
		    "    slot <hex>\n"
		    "    key <'ecdsa-sha2-nistp256 AA...'>       Sets 9d key\n"
		    "    cak <'ecdsa-sha2-nistp256 AA...'>       Sets 9e key\n"
		    "  add-recovery < ...>    Add a new recovery config\n"
		    "    require <int>        Set # of parts required\n"
		    "    part < ... >         Specifies a part for the config\n"
		    "      name/guid/slot/key\n");
	} else if (strcmp(op, "show") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl show [-r] [tpl]\n"
		    "\n"
		    "Pretty-prints a template to stdout showing details of\n"
		    "devices and configuration.\n"
		    "\n"
		    "Options:\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "\n"
		    "If no [tpl] or -f given, expects template input on stdin.\n");
	} else if (strcmp(op, "list") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl list\n"
		    "\n"
		    "Lists templates stored in the standard template path, with\n"
		    "brief information about each.\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box tpl <op>:\n"
		    "  create                Create a new template\n"
		    "  edit                  Edit an existing template\n"
		    "  show                  Pretty-print a template to stdout\n"
		    "  list                  List templates in default path\n");
		fprintf(stderr, "If not using -f, templates are stored in:\n");
		tpe = ebox_tpl_path;
		while (tpe != NULL) {
			dpath = compose_path(tpe->tpe_segs, "");
			fprintf(stderr, "  * %s\n", dpath);
			free(dpath);
			tpe = tpe->tpe_next;
		}
	}
}

static void
usage_key(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "generate") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key generate [-R] [-l len] <tpl>\n"
		    "\n"
		    "Generates random key material of a specified length\n"
		    "(default 16 bytes), encrypts it with an ebox and outputs\n"
		    "just the ebox.\n"
		    "\n"
		    "Options:\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "  -l len     set length of key in bytes\n"
		    "\n");
	} else if (strcmp(op, "info") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key info [-r]\n"
		    "\n"
		    "Pretty-prints information about a 'key' ebox.\n"
		    "\n"
		    "Options:\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "\n");
	} else if (strcmp(op, "lock") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key lock [-rR] <tpl>\n"
		    "\n"
		    "Takes pre-generated key material and encrypts it with\n"
		    "a 'key' ebox. This is not suitable for large amounts\n"
		    "of data.\n"
		    "\n"
		    "Options:\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "\n");
	} else if (strcmp(op, "unlock") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key unlock [-brR] [file]\n"
		    "\n"
		    "Decrypts a 'key' ebox and outputs the contents.\n"
		    "\n"
		    "Options:\n"
		    "  -b         batch mode, don't talk to terminal\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "\n");
	} else if (strcmp(op, "relock") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key relock [-brR] <newtpl> [file]\n"
		    "\n"
		    "Decrypts a 'key' ebox and then re-encrypts it with a new\n"
		    "template. Can be used to update an ebox after editing\n"
		    "the template to add/remove devices.\n"
		    "\n"
		    "Options:\n"
		    "  -b         batch mode, don't talk to terminal\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box key <op>:\n"
		    "  generate              Generate a random key and ebox it\n"
		    "  lock                  Ebox a pre-generated key\n"
		    "  info                  Prints information about a key ebox\n"
		    "  unlock                Unlock a key ebox\n"
		    "  relock                Unlock + lock to new template\n");
	}
}

static void
usage_stream(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "encrypt") == 0) {
		fprintf(stderr,
		    "usage: pivy-box stream encrypt <tpl>\n"
		    "\n"
		    "Accepts streaming data on stdin and encrypts it to the\n"
		    "given template in chunks. Output is binary.\n");
	} else if (strcmp(op, "decrypt") == 0) {
		fprintf(stderr,
		    "usage: pivy-box stream decrypt [-b] [file]\n"
		    "\n"
		    "Accepts output from 'stream encrypt' on stdin, decrypts\n"
		    "it and outputs the plaintext. Data is only output after\n"
		    "it has been authenticated/validated.\n"
		    "\n"
		    "Options:\n"
		    "  -b         batch mode, don't talk to terminal\n"
		    "\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box stream <op>:\n"
		    "  encrypt               Encrypt streaming data\n"
		    "  decrypt               Decrypt streaming data\n");
	}
}

static void
usage_challenge(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "info") == 0) {
		fprintf(stderr,
		    "usage: pivy-box challenge info\n"
		    "\n"
		    "Takes a recovery challenge (such as that output by\n"
		    "the 'key unlock' or 'stream decrypt' commands), decrypts\n"
		    "it, and prints the contained information to stdout.\n");
	} else if (strcmp(op, "respond") == 0) {
		fprintf(stderr,
		    "usage: pivy-box challenge respond\n"
		    "\n"
		    "Takes a recovery challenge (such as that output by\n"
		    "the 'key unlock' or 'stream decrypt' commands), decrypts\n"
		    "it, prints the contained information to stdout, then\n"
		    "waits for user confirmation before generating a response.\n"
		    "\n"
		    "The response must then be transported back to the program\n"
		    "which generated the challenge to complete the process.\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box challenge <op>:\n"
		    "  info                  Show information about a recovery\n"
		    "                        challenge without responding\n"
		    "  respond               Respond to a recovery challenge\n");
	}
}

static void
usage(const char *type, const char *op)
{
	if (type == NULL) {
		usage_types();
	} else if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {
		usage_tpl(op);
	} else if (strcmp(type, "key") == 0) {
		usage_key(op);
	} else if (strcmp(type, "stream") == 0) {
		usage_stream(op);
	} else if (strcmp(type, "challenge") == 0) {
		usage_challenge(op);
	} else {
		usage_types();
	}
	exit(EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	const char *optstring = "bl:irRP:i:o:f:";
	const char *type = NULL, *op = NULL, *tplname;
	int c;
	char tpl[PATH_MAX] = { 0 };
	errf_t *error = NULL;
	unsigned long int parsed;
	char *p;

	qa_term_setup();
	parse_tpl_path_env();

	if (argc < 2) {
		warnx("type and operation required");
		usage(type, op);
		return (EXIT_USAGE);
	}
	type = argv[1];
	if (argc < 3) {
		warnx("operation required");
		usage(type, op);
		return (EXIT_USAGE);
	}
	op = argv[2];

	argc -= 2;
	argv += 2;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'b':
			ebox_batch = B_TRUE;
			break;
		case 'r':
			ebox_raw_in = B_TRUE;
			break;
		case 'R':
			ebox_raw_out = B_TRUE;
			break;
		case 'f':
			strlcpy(tpl, optarg, sizeof (tpl));
			break;
		case 'i':
			ebox_interactive = B_TRUE;
			break;
		case 'l':
			if (strcmp(type, "key") != 0 ||
			    strcmp(op, "generate") != 0) {
				warnx("option -l only supported with "
				    "'key generate' subcommand");
				usage(type, op);
				return (EXIT_USAGE);
			}
			errno = 0;
			parsed = strtoul(optarg, &p, 0);
			if (errno != 0 || *p != '\0') {
				errx(EXIT_USAGE,
				    "invalid argument for -l: '%s'", optarg);
			}
			ebox_keylen = parsed;
			break;
		default:
			usage(type, op);
			return (EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {
		if (strcmp(op, "show") == 0 && argc == 0 && tpl[0] == 0) {
			error = cmd_tpl_show(argc, argv);
			goto out;
		} else if (strcmp(op, "list") == 0 && argc == 0) {
			error = cmd_tpl_list(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "key") == 0) {
		if (strcmp(op, "unlock") == 0) {
			error = cmd_key_unlock(argc, argv);
			goto out;
		} else if (strcmp(op, "info") == 0) {
			error = cmd_key_info(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "stream") == 0) {
		if (strcmp(op, "decrypt") == 0) {
			error = cmd_stream_decrypt(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "challenge") == 0) {
		if (strcmp(op, "info") == 0) {
			error = cmd_challenge_info(argc, argv);
			goto out;

		} else if (strcmp(op, "respond") == 0) {
			error = cmd_challenge_respond(argc, argv);
			goto out;
		}
		goto badop;
	}

	if (tpl[0] == '\0') {
		char *tmp;
		if (argc < 1) {
			warnx("template name or path required");
			usage(type, op);
			return (EXIT_USAGE);
		}
		tplname = argv[0];

		argc--;
		argv++;
		tmp = access_tpl_file(tplname, F_OK);
		if (tmp == NULL)
			tmp = access_tpl_file(tplname, W_OK);
		if (tmp == NULL) {
			warnx("no writable template path could be found");
			return (EXIT_USAGE);
		}
		strlcpy(tpl, tmp, sizeof (tpl));
		free(tmp);
	}

	if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {

		if (strcmp(op, "create") == 0) {
			error = cmd_tpl_create(tpl, argc, argv);
			goto out;

		} else if (strcmp(op, "edit") == 0) {
			ebox_stpl = read_tpl_file(tpl);
			error = cmd_tpl_edit(tpl, argc, argv);
			goto out;

		} else if (strcmp(op, "show") == 0) {
			ebox_stpl = read_tpl_file(tpl);
			error = cmd_tpl_show(argc, argv);
			goto out;

		}

	} else if (strcmp(type, "key") == 0) {

		if (strcmp(op, "generate") == 0) {
			ebox_stpl = read_tpl_file(tpl);
			error = cmd_key_generate(argc, argv);
			goto out;

		} else if (strcmp(op, "lock") == 0) {
			ebox_stpl = read_tpl_file(tpl);
			error = cmd_key_lock(argc, argv);
			goto out;

		} else if (strcmp(op, "unlock") == 0) {
			error = cmd_key_unlock(argc, argv);
			goto out;

		} else if (strcmp(op, "relock") == 0) {
			ebox_stpl = read_tpl_file(tpl);
			error = cmd_key_relock(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "stream") == 0) {

		if (strcmp(op, "decrypt") == 0) {
			error = cmd_stream_decrypt(argc, argv);
			goto out;

		} else if (strcmp(op, "encrypt") == 0) {
			ebox_stpl = read_tpl_file(tpl);
			error = cmd_stream_encrypt(argc, argv);
			goto out;
		}

	}
badop:
	warnx("unknown operation: '%s %s'", type, op);
	usage(type, op);
	return (EXIT_USAGE);

out:
	if (error)
		errfx(EXIT_ERROR, error, "'%s %s' command failed", type, op);
	return (0);
}

void
cleanup_exit(int i)
{
	exit(i);
}
