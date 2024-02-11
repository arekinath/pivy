/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2021, The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
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
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>
#include <sys/stat.h>

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <json.h>

int PEM_write_X509(FILE *fp, X509 *x);

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"
#include "pkinit_asn1.h"
#include "piv-ca.h"
#include "ebox-cmd.h"

/* We need the piv_cert_comp enum */
#include "piv-internal.h"

#if defined(__sun) || defined(__APPLE__)
#include <netinet/in.h>
#define	be16toh(v)	(ntohs(v))
#else
#include <endian.h>
#endif

#if !defined(JSONC_14)
size_t json_tokener_get_parse_end(struct json_tokener *);
/* compat version will be defined by piv-ca.c on <=0.14 */
#endif

boolean_t debug = B_FALSE;
static struct cert_var_scope *root_scope = NULL;
static struct piv_ctx *ctx;
static boolean_t output_json = B_FALSE;

#ifndef LINT
#define	funcerrf(cause, fmt, ...)	\
    errf(__func__, cause, fmt , ##__VA_ARGS__)
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))
#endif

enum pivca_exit_status {
	/*EXIT_OK = 0,
	EXIT_USAGE = 1,
	EXIT_ERROR = 2,
	EXIT_INTERACTIVE = 3,
	EXIT_PIN = 4,
	EXIT_PIN_LOCKED = 5,
	EXIT_ALREADY_UNLOCKED = 6,*/
	EXIT_NO_CARD = 7,
	EXIT_IO_ERROR = 8,

	EXIT_BAD_ARGS = EXIT_USAGE,
};

static const uint8_t DEFAULT_ADMIN_KEY[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

#if defined(__sun)
const char *
_umem_debug_init()
{
	return ("guards");
}
#endif

void
usage(void)
{
	fprintf(stderr,
	    "usage: pivy-ca [options] <operation>\n"
	    "\n"
	    "Operates an X.509 CA with key stored on a PIV card\n"
	    "\n"
	    "Available operations:\n"
	    "  setup                     Create a new CA with an empty PIV card\n"
	    "  shell                     Start a shell in a pivy-agent for the CA\n"
	    "  show                      Show info about the CA\n"
	    "  list-tpl                  List base templates known to pivy-ca\n"
	    "  sign-config               Re-sign config JSON\n"
	    "  sign-req [path] [tpl]     Sign a CSR (cert request) from path or stdin\n"
	    "  revoke-cert [path]        Revoke a certificate\n"
	    "  revoke-serial [hex]       Revoke using just a serial number\n"
	    "  sign-crl                  Signs a new CRL for the CA\n"
	    "  rotate-pin                Generates a new PIN for the CA card\n"
	    "\n"
	    "General options:\n"
	    "  -p <path>                 Path to dir containing pivy-ca.json\n"
	    "  -D <key=value>            Defines a certificate variable\n"
	    "  -J <path>                 Path to a JSON file containing cert vars\n"
	    "  -j                        Output in JSON format (from e.g. sign-req)\n"
	    "  -d                        Enable debug logging\n"
	    "\n");
	exit(EXIT_BAD_ARGS);
}

static errf_t *
ensure_authed(struct ca *ca, struct ca_session *sess)
{
	errf_t *err;
	enum piv_pin type;
	struct ebox *box;
	uint8_t *k;
	size_t klen;
	char pin[16];

	if (ca_session_authed(sess))
		return (ERRF_OK);

	fprintf(stderr, "Unlocking PIN for CA '%s'...\n", ca_slug(ca));

	type = ca_session_auth_type(sess);
	box = ca_get_ebox(ca, CA_EBOX_PIN);

	err = interactive_unlock_ebox(box, ca_slug(ca));
	if (err != ERRF_OK) {
		err = errf("CAPINError", err, "failed to unlock PIN for CA");
		return (err);
	}

	k = (uint8_t *)ebox_key(box, &klen);
	VERIFY(klen < sizeof (pin));
	bzero(pin, sizeof (pin));
	bcopy(k, pin, klen);
	/* Just in case there's a newline or other whitespace after the PIN */
	while (isspace(pin[klen - 1])) {
		--klen;
		pin[klen] = '\0';
	}

	err = ca_session_auth(sess, type, pin);
	explicit_bzero(pin, sizeof (pin));

	return (err);
}

errf_t *read_text_file(const char *path, char **out, size_t *outlen);

struct cvpriv {
	struct cert_var	*cvp_cv;
	struct answer	*cvp_ans;
};

static errf_t *
prompt_scope(struct cert_var_scope *scope)
{
	errf_t *err;
	char *line;
	struct question *q;
	struct answer *a;
	struct answer *issue_ans;
	struct cert_var *all, *var;
	struct cvpriv *p;
	char k = '1';
	boolean_t issue_in = B_FALSE;
	uint undef = 0;
	char *tmp;
	uint qinit;

	undef = 0;
	all = scope_all_vars(scope);
	for (var = all; var != NULL; var = cert_var_next(var)) {
		if (!cert_var_required(var, REQUIRED_FOR_CERT))
			continue;
		if (!cert_var_defined(var))
			++undef;
	}
	if (undef == 0)
		return (ERRF_OK);

	qa_term_setup();

	q = calloc(1, sizeof (struct question));
	VERIFY(q != NULL);
	question_printf(q, "-- Certificate variables --\n");
	question_printf(q, "Some certificate variables required for this "
	    "template are not yet defined.\n");
	qinit = q->q_used;

	issue_ans = make_answer('.', "Issue certificate");

prompt:
	undef = 0;
	q->q_used = qinit;
	all = scope_all_vars(scope);

	for (var = all; var != NULL; var = cert_var_next(var)) {
		if (!cert_var_required(var, REQUIRED_FOR_CERT))
			continue;
		if (!cert_var_defined(var))
			++undef;
	}

	question_printf(q, "\n-- Available pre-defined variables --\n");
	question_printf(q, "      %-16s  %-40s  %-40s\n",
	    "VARIABLE", "RAW VALUE", "EVALUATION");
	for (var = all; var != NULL; var = cert_var_next(var)) {
		if (!cert_var_defined(var))
			continue;
		tmp = cert_var_value(var);
		question_printf(q, "      %-16s  %-40s",
		    cert_var_name(var),
		    tmp == NULL ? "(undefined)" : tmp);
		free(tmp);
		err = cert_var_eval(var, &tmp);
		if (err != ERRF_OK) {
			errf_free(err);
			question_printf(q, "  (error)\n");
		} else {
			question_printf(q, "  %-40s\n", tmp);
			free(tmp);
		}
	}

	question_printf(q, "\n-- Required variables --\n");
	question_printf(q, "      %-16s  %-40s  %-40s",
	    "VARIABLE", "RAW VALUE", "EVALUATION");
	for (var = all; var != NULL; var = cert_var_next(var)) {
		if (!cert_var_required(var, REQUIRED_FOR_CERT))
			continue;
		p = cert_var_private(var);
		if (!cert_var_defined(var) && p == NULL) {
			p = cert_var_alloc_private(var, sizeof (struct cvpriv));
			VERIFY(p != NULL);
			p->cvp_cv = var;

			tmp = cert_var_value(var);
			p->cvp_ans = make_answer(k++, "%-16s  %-40s",
			    cert_var_name(var),
			    tmp == NULL ? "(undefined)" : tmp);
			free(tmp);
			p->cvp_ans->a_priv = p;
			add_answer(q, p->cvp_ans);

			err = cert_var_eval(var, &tmp);
			if (err != ERRF_OK) {
				errf_free(err);
				answer_printf(p->cvp_ans, "  (error)");
			} else {
				answer_printf(p->cvp_ans, "  %-40s", tmp);
				free(tmp);
			}
			if (k > '9' && k < 'a')
				k = 'a';
		} else if (p != NULL) {
			p->cvp_ans->a_used = 0;
			tmp = cert_var_value(var);
			answer_printf(p->cvp_ans, "%-16s  %-40s",
			    cert_var_name(var),
			    tmp == NULL ? "(undefined)" : tmp);
			free(tmp);
			err = cert_var_eval(var, &tmp);
			if (err != ERRF_OK) {
				errf_free(err);
				answer_printf(p->cvp_ans, "  (error)");
			} else {
				answer_printf(p->cvp_ans, "  %-40s", tmp);
				free(tmp);
			}
		}

	}
	if (undef == 0 && !issue_in) {
		add_command(q, issue_ans);
		issue_in = B_TRUE;
	} else if (undef > 0 && issue_in) {
		remove_command(q, issue_ans);
		issue_in = B_FALSE;
	}
again:
	question_prompt(q, &a);
	if (a != issue_ans) {
		p = a->a_priv;
		var = p->cvp_cv;

		line = readline("New value? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		if (strlen(line) < 1)
			goto again;

		err = cert_var_set(var, line);
		if (err != ERRF_OK) {
			warnfx(err, "failed to set %s", cert_var_name(var));
			errf_free(err);
		}
		err = scope_set(root_scope, cert_var_name(var), line);
		if (err != ERRF_OK) {
			warnfx(err, "failed to set %s", cert_var_name(var));
			errf_free(err);
		}
		goto prompt;
	}

	err = ERRF_OK;

	for (var = all; var != NULL; var = cert_var_next(var)) {
		cert_var_free_private(var);
	}
	question_free(q);
	return (err);
}

static int
is_uninit(struct piv_token *tok)
{
	const struct piv_fascn *fascn;
	const struct piv_chuid *chuid;
	chuid = piv_token_chuid(tok);
	if (chuid == NULL)
		return (1);
	if (piv_chuid_is_signed(chuid))
		return (0);
	fascn = piv_chuid_get_fascn(chuid);
	if (fascn == NULL)
		return (1);
	if (strcmp(piv_fascn_get_agency_code(fascn), "0000") != 0 &&
	    strcmp(piv_fascn_get_system_code(fascn), "0000") != 0 &&
	    strcmp(piv_fascn_get_cred_number(fascn), "000000") != 0)
		return (0);
	if (strcmp(piv_chuid_get_guidhex(chuid),
	    "00000000000000000000000000000000") == 0)
		return (1);
	return (0);
}

static errf_t *
cmd_setup(const char *ca_path)
{
	/*
	 * collect info:
	 *  - CA's DN,
	 *  - CRL URLs
	 *  - constraints (e.g. nameconstraints)
	 *  - CRL timing settings
	 *  - key gen settings
	 *
	 * provision config:
	 *  - pin, puk and admin key
	 *  - require attestation? choose attestation CAs
	 *  - templates and slots
	 *  - variable definitions (and free variables)
	 */
	struct ca_new_args *cna;
	X509_NAME *dn, *newdn;
	struct ebox_tpl *tpl;
	struct ca *ca;
	struct piv_token *tokens, *tok;
	errf_t *err;
	char *line;
	struct question *q;
	struct answer *a;
	enum piv_alg alg = PIV_ALG_RSA2048;
	char *pin_tpl_name = NULL, *puk_tpl_name = NULL,
	    *backup_tpl_name = NULL;
	char *lifetime = strdup("20y");
	char *dnstr = strdup("cn=Example CA");
	struct ebox_tpl *pin_tpl = NULL, *puk_tpl = NULL, *backup_tpl = NULL;
	struct answer *dn_ans, *life_ans, *alg_ans, *pin_tpl_ans, *puk_tpl_ans,
	    *backup_tpl_ans, *cont_ans;

	err = piv_enumerate(ctx, &tokens);
	if (err)
		errfx(EXIT_IO_ERROR, err, "failed to enumerate PIV tokens");
	if (tokens == NULL)
		errx(EXIT_NO_CARD, "no PIV cards/tokens found");
	for (tok = tokens; tok != NULL; tok = piv_token_next(tok)) {
		if (is_uninit(tok))
			break;
	}
	if (tok == NULL || !is_uninit(tok))
		errx(EXIT_NO_CARD, "no uninit'd PIV token/card found");

	fprintf(stderr, "Setting up new CA in device '%s'...\n",
	    piv_token_rdrname(tok));

	dn = X509_NAME_new();
	err = parse_dn(dnstr, dn);
	VERIFY(err == ERRF_OK);

	qa_term_setup();
	parse_tpl_path_env();

	q = calloc(1, sizeof (struct question));
	VERIFY(q != NULL);
	question_printf(q, "-- CA configuration --\n");

	dn_ans = make_answer('1', "CA DN: %s", dnstr);
	alg_ans = make_answer('2', "Private key type: %s",
	    piv_alg_to_string(alg));
	life_ans = make_answer('3', "Lifetime: %s", lifetime);
	pin_tpl_ans = make_answer('4', "Ebox template for PIN: %s",
	    pin_tpl == NULL ? "(none)" : pin_tpl_name);
	puk_tpl_ans = make_answer('5', "Ebox template for PUK: %s",
	    puk_tpl == NULL ? "(none)" : puk_tpl_name);
	backup_tpl_ans = make_answer('6', "Ebox template for key backup: %s",
	    backup_tpl == NULL ? "(none)" : backup_tpl_name);
	cont_ans = make_answer('c', "Continue");

	add_answer(q, dn_ans);
	add_answer(q, alg_ans);
	add_answer(q, life_ans);
	add_answer(q, pin_tpl_ans);
	add_answer(q, puk_tpl_ans);
	add_answer(q, backup_tpl_ans);
	add_command(q, cont_ans);

again:
	question_prompt(q, &a);
	if (a == dn_ans) {
		line = readline("CA DN? ");
		if (line == NULL)
			exit(EXIT_ERROR);

		newdn = X509_NAME_new();
		err = parse_dn(line, newdn);
		if (err != ERRF_OK) {
			warnfx(err, "failed to parse DN");
			X509_NAME_free(newdn);
			errf_free(err);
			goto again;
		}
		free(dnstr);
		X509_NAME_free(dn);
		dnstr = line;
		dn = newdn;
		a->a_used = 0;
		answer_printf(a, "CA DN: %s", dnstr);
		goto again;
	} else if (a == life_ans) {
		unsigned long secs;
		line = readline("Lifetime? ");
		if (line == NULL)
			exit(EXIT_ERROR);

		err = parse_lifetime(line, &secs);
		if (err != ERRF_OK) {
			warnfx(err, "failed to parse lifetime");
			errf_free(err);
			free(line);
			goto again;
		}
		free(lifetime);
		lifetime = line;
		a->a_used = 0;
		answer_printf(a, "Lifetime: %s", lifetime);
		goto again;
	} else if (a == alg_ans) {
		line = readline("Private key type? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		err = piv_alg_from_string(line, &alg);
		free(line);
		if (err) {
			warnfx(err, "error parsing input");
			errf_free(err);
		}
		a->a_used = 0;
		answer_printf(a, "Private key type: %s",
		    piv_alg_to_string(alg));
		goto again;
	} else if (a == pin_tpl_ans) {
		line = readline("PIN template? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		err = read_tpl_file_err(line, &tpl);
		if (err) {
			warnfx(err, "error parsing input");
			errf_free(err);
			free(line);
		} else {
			pin_tpl = tpl;
			pin_tpl_name = line;
		}
		a->a_used = 0;
		answer_printf(a, "Ebox template for PIN: %s", pin_tpl_name);
		goto again;
	} else if (a == puk_tpl_ans) {
		line = readline("PUK template? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		err = read_tpl_file_err(line, &tpl);
		if (err) {
			warnfx(err, "error parsing input");
			errf_free(err);
			free(line);
		} else {
			puk_tpl = tpl;
			puk_tpl_name = line;
		}
		a->a_used = 0;
		answer_printf(a, "Ebox template for PUK: %s", puk_tpl_name);
		goto again;
	} else if (a == backup_tpl_ans) {
		line = readline("Backup template? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		err = read_tpl_file_err(line, &tpl);
		if (err) {
			warnfx(err, "error parsing input");
			errf_free(err);
			free(line);
		} else {
			backup_tpl = tpl;
			backup_tpl_name = line;
		}
		a->a_used = 0;
		answer_printf(a, "Ebox template for PUK: %s", backup_tpl_name);
		goto again;
	} else if (a == cont_ans) {
		if (pin_tpl == NULL) {
			fprintf(stderr, "error: PIN template required\n");
			goto again;
		}
		if (puk_tpl == NULL) {
			fprintf(stderr, "error: PUK template required\n");
			goto again;
		}
		if (backup_tpl == NULL) {
			fprintf(stderr, "error: backup template required\n");
			goto again;
		}
	} else {
		goto again;
	}

	scope_set(root_scope, "lifetime", lifetime);

	cna = cana_new();
	cana_scope(cna, root_scope);
	cana_initial_pin(cna, "123456");
	cana_initial_puk(cna, "12345678");
	cana_initial_admin_key(cna, PIV_ALG_3DES, DEFAULT_ADMIN_KEY, 24);
	cana_key_alg(cna, alg);
	cana_dn(cna, dn);
	cana_pin_tpl(cna, pin_tpl_name, pin_tpl);
	cana_backup_tpl(cna, backup_tpl_name, backup_tpl);
	cana_puk_tpl(cna, puk_tpl_name, puk_tpl);

	fprintf(stderr, "Generating and signing initial CA configuration...\n");

	err = ca_generate(ca_path, cna, tok, &ca);
	if (err)
		return (err);

	ca_close(ca);

	return (ERRF_OK);
}

struct log_iter_state {
	size_t	 lis_issued;
	size_t	 lis_revoked;
	size_t	 lis_crls;
	char	*lis_last_crl;
	char	*lis_last_issue_json;
};

static void
log_iter(json_object *entry, void *cookie)
{
	struct log_iter_state *s = cookie;
	json_object *obj;
	const char *action;

	obj = json_object_object_get(entry, "action");
	if (obj == NULL)
		return;
	action = json_object_get_string(obj);
	if (action == NULL)
		return;

	if (strcmp(action, "issue_cert") == 0) {
		++s->lis_issued;

		free(s->lis_last_issue_json);
		json_object_object_del(entry, "prev_hash");
		json_object_object_del(entry, "signature");
		json_object_object_del(entry, "action");
		json_object_object_del(entry, "time_secs");
		s->lis_last_issue_json = strdup(json_object_get_string(entry));

	} else if (strcmp(action, "revoke_cert") == 0) {
		++s->lis_revoked;

	} else if (strcmp(action, "gen_crl") == 0) {
		++s->lis_crls;

		free(s->lis_last_crl);
		obj = json_object_object_get(entry, "time");
		s->lis_last_crl = strdup(json_object_get_string(obj));
	}
}

static errf_t *
cmd_list_tpl(const char *ca_path, const char *tpl_name)
{
	const struct cert_tpl *tpl;
	struct cert_var *all, *var;

	if (tpl_name == NULL)
		tpl = cert_tpl_first();
	else
		tpl = cert_tpl_find(tpl_name);

	for (; tpl != NULL; tpl = cert_tpl_next(tpl)) {
		fprintf(stderr, "-- Base template '%s' --\n",
		    cert_tpl_name(tpl));
		fprintf(stderr, "Name:            %s\n",
			    cert_tpl_name(tpl));
		if (cert_tpl_help(tpl) != NULL) {
			fprintf(stderr, "Help text:       %s\n",
			    cert_tpl_help(tpl));
		}
		all = cert_tpl_vars(tpl);
		fprintf(stderr, "\n  -- Parameters --\n");
		for (var = all; var != NULL; var = cert_var_next(var)) {
			fprintf(stderr, "  Name:          %s\n",
			    cert_var_name(var));
			if (cert_var_required(var, REQUIRED_FOR_CERT))
				fprintf(stderr, "  Required:      yes\n");
			fprintf(stderr, "  Help:          %s\n",
			    cert_var_help(var));
			fprintf(stderr, "\n");
		}
		cert_var_free_all(all);
		fprintf(stderr, "\n");
		if (tpl_name != NULL)
			break;
	}

	return (ERRF_OK);
}

static errf_t *
cmd_show(const char *ca_path)
{
	struct ca *ca;
	char *dn;
	uint i;
	struct log_iter_state s;
	errf_t *err;
	struct ca_cert_tpl *tpl;
	struct cert_var_scope *ca_scope, *cert_scope;
	enum ca_cert_tpl_flags flags;
	struct cert_var *all, *var;
	const struct cert_tpl *ctpl;

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	dn = ca_dn(ca);
	fprintf(stderr, "Using pivy-ca in '%s'\n\n", ca_path);
	fprintf(stderr, "-- CA properties --\n");
	fprintf(stderr, "DN:              %s\n", dn);
	free(dn);
	fprintf(stderr, "Slug:            %s\n", ca_slug(ca));
	fprintf(stderr, "GUID:            %s\n", ca_guidhex(ca));
	for (i = 0; i < ca_crl_uri_count(ca); ++i) {
		fprintf(stderr, "CRL:             %s\n", ca_crl_uri(ca, i));
	}
	for (i = 0; i < ca_ocsp_uri_count(ca); ++i) {
		fprintf(stderr, "OCSP:            %s\n", ca_ocsp_uri(ca, i));
	}
	fprintf(stderr, "\nPublic key:\n");
	VERIFY0(sshkey_write(ca_pubkey(ca), stderr));

	fprintf(stderr, "\n\n-- CA log --\n");
	bzero(&s, sizeof (s));
	err = ca_log_verify(ca, NULL, log_iter, &s);

	fprintf(stderr, "Issued:          %zu\n", s.lis_issued);
	fprintf(stderr, "Revoked:         %zu\n", s.lis_revoked);
	fprintf(stderr, "CRLs generated:  %zu\n", s.lis_crls);

	fprintf(stderr, "Last CRL:        %s\n",
	    s.lis_last_crl == NULL ? "(never)" : s.lis_last_crl);
	fprintf(stderr, "Last issue:      %s\n",
	    s.lis_last_issue_json == NULL ? "(none)" : s.lis_last_issue_json);
	free(s.lis_last_crl);
	free(s.lis_last_issue_json);

	if (err != ERRF_OK) {
		warnfx(err, "CA log failed to verify");
		errf_free(err);
	}

	ca_scope = ca_make_scope(ca, root_scope);
	VERIFY(ca_scope != NULL);

	tpl = ca_cert_tpl_first(ca);
	for (; tpl != NULL; tpl = ca_cert_tpl_next(tpl)) {
		fprintf(stderr, "\n-- Cert Template '%s' --\n",
		    ca_cert_tpl_name(tpl));
		if (ca_cert_tpl_help(tpl) != NULL) {
			fprintf(stderr, "Help text:       %s\n",
			    ca_cert_tpl_help(tpl));
		}
		flags = ca_cert_tpl_flags(tpl);
		fprintf(stderr, "Flags:           ");
		if (flags & CCTF_SELF_SIGNED)
			fprintf(stderr, "self-signed ");
		if (flags & CCTF_ALLOW_REQS)
			fprintf(stderr, "allow-reqs ");
		if (flags & CCTF_COPY_DN)
			fprintf(stderr, "copy-DN ");
		if (flags & CCTF_COPY_KP)
			fprintf(stderr, "copy-KPs ");
		if (flags & CCTF_COPY_SAN)
			fprintf(stderr, "copy-SANs ");
		if (flags & CCTF_COPY_OTHER_EXTS)
			fprintf(stderr, "copy-extensions ");
		if (flags & CCTF_KEY_BACKUP)
			fprintf(stderr, "key-backup ");
		if (flags & CCTF_HOST_KEYGEN)
			fprintf(stderr, "host-keygen");
		fprintf(stderr, "\n");

		ctpl = ca_cert_tpl_tpl(tpl);
		fprintf(stderr, "Base template:   %s\n", cert_tpl_name(ctpl));

		fprintf(stderr, "Parameters:      ");
		cert_scope = ca_cert_tpl_make_scope(tpl, ca_scope);
		VERIFY(cert_scope != NULL);
		all = scope_all_vars(cert_scope);
		for (var = all; var != NULL; var = cert_var_next(var)) {
			if (!cert_var_required(var, REQUIRED_FOR_CERT))
				continue;
			if (cert_var_defined(var))
				continue;
			fprintf(stderr, "%s ", cert_var_name(var));
		}
		fprintf(stderr, "\n");
	}

	ca_close(ca);

	return (ERRF_OK);
}

static errf_t *
cmd_shell(const char *ca_path, int is_child)
{
	errf_t *err;
	struct ca *ca;
	const char *shell = "sh";
	const char *tmp;
	char *argv[16];
	uint i = 0;
	struct sshbuf *buf;
	int rc;
	pid_t kid, waited;
	struct ca_session *sess;
	int stat;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	tmp = getenv("SHELL");
	if (tmp != NULL)
		shell = tmp;

	if (is_child) {
		fprintf(stderr, "Agent started, ready to auth...\n");
		err = ca_open_session(ca, &sess);
		if (err != ERRF_OK)
			return (err);

		err = ensure_authed(ca, sess);
		if (err != ERRF_OK)
			return (err);

		ca_close_session(sess);

		fprintf(stderr, "Starting shell '%s'\n", shell);
		kid = fork();
		if (kid < 0) {
			err = errfno("fork", errno, "forking child");
			return (err);
		}

		if (kid == 0) {
			argv[i++] = strdup("env");
			argv[i++] = strdup("PIVY_CA_SHELL=yes");
			argv[i++] = strdup(shell);
			argv[i++] = NULL;
			rc = execvp("env", argv);
			if (rc < 0) {
				err = errfno("execv", errno, "executing pivy-agent");
				return (err);
			}
		}

		waited = waitpid(kid, &stat, 0);
		VERIFY3U(waited, ==, kid);
		if (WIFSIGNALED(stat)) {
			err = errf("ChildCrashed", NULL, "Shell child process "
			    "exited on signal %d", WTERMSIG(stat));
			return (err);
		}
		if (WEXITSTATUS(stat) != 0) {
			err = errf("ChildExitStatus", NULL, "Shell child "
			    "process exited with status %d", WEXITSTATUS(stat));
			return (err);
		}

		fprintf(stderr, "Rotating CA PIN...\n");

		unsetenv("SSH_AUTH_SOCK");
		err = ca_open_session(ca, &sess);
		if (err != ERRF_OK) {
			err = errf("PINRotateError", err, "failed to open"
			    "session with card to rotate PIN");
			return (err);
		}

		err = ensure_authed(ca, sess);
		if (err != ERRF_OK)
			return (err);

		err = ca_rotate_pin(sess);
		if (err != ERRF_OK)
			return (err);

		ca_close_session(sess);
		ca_close(ca);

	} else {
		rc = sshkey_format_text(ca_cak(ca), buf);
		if (rc != 0) {
			err = ssherrf("sshkey_format_text", rc);
			return (err);
		}

		argv[i++] = strdup("pivy-agent");
		argv[i++] = strdup("-g");
		argv[i++] = strdup(ca_guidhex(ca));
		argv[i++] = strdup("-K");
		argv[i++] = sshbuf_dup_string(buf);
		argv[i++] = strdup("--");
		argv[i++] = strdup("pivy-ca");
		argv[i++] = strdup("-K");
		argv[i++] = strdup("shell");
		argv[i++] = NULL;

		rc = execvp("pivy-agent", argv);
		if (rc < 0) {
			err = errfno("execv", errno, "executing pivy-agent");
			return (err);
		}
	}

	return (ERRF_OK);
}

static errf_t *
cmd_sign_config(const char *ca_path)
{
	errf_t *err;
	struct ca *ca;
	struct ca_session *sess;

	(void) setenv("PIVY_CA_UNSIGNED", "yes-i-really-want-no-security", 0);

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	err = ca_open_session(ca, &sess);
	if (err != ERRF_OK)
		return (err);

	err = ensure_authed(ca, sess);
	if (err != ERRF_OK)
		return (err);

	err = ca_config_write(ca, sess);
	if (err != ERRF_OK)
		return (err);

	ca_close_session(sess);
	ca_close(ca);

	return (ERRF_OK);
}

static errf_t *
cmd_rotate_pin(const char *ca_path)
{
	errf_t *err;
	struct ca *ca;
	struct ca_session *sess;

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	err = ca_open_session(ca, &sess);
	if (err != ERRF_OK)
		return (err);

	err = ensure_authed(ca, sess);
	if (err != ERRF_OK)
		return (err);

	err = ca_rotate_pin(sess);
	if (err != ERRF_OK)
		return (err);

	ca_close_session(sess);
	ca_close(ca);

	return (ERRF_OK);
}

static errf_t *
cmd_sign_crl(const char *ca_path)
{
	errf_t *err;
	struct ca *ca;
	struct ca_session *sess;
	X509_CRL *crl;

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	err = ca_open_session(ca, &sess);
	if (err != ERRF_OK)
		return (err);

	err = ensure_authed(ca, sess);
	if (err != ERRF_OK)
		return (err);

	crl = X509_CRL_new();
	VERIFY(crl != NULL);

	err = ca_generate_crl(ca, sess, crl);
	if (err != ERRF_OK)
		return (err);

	PEM_write_X509_CRL(stdout, crl);
	X509_CRL_free(crl);

	ca_close_session(sess);
	ca_close(ca);

	return (ERRF_OK);
}

static errf_t *
cmd_revoke_cert(const char *ca_path, const char *cert_path)
{
	FILE *f = NULL;
	errf_t *err;
	struct stat st;
	X509 *cert;
	struct ca *ca;
	struct ca_session *sess;
	int rc;
	BIO *bio;

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	err = ca_open_session(ca, &sess);
	if (err != ERRF_OK)
		return (err);

	err = ensure_authed(ca, sess);
	if (err != ERRF_OK)
		return (err);

	if (cert_path == NULL || strcmp(cert_path, "-") == 0) {
		f = stdin;
	} else {
		f = fopen(cert_path, "r");
		if (f == NULL) {
			err = errfno("fopen", errno, "opening '%s'", cert_path);
			return (err);
		}
		bzero(&st, sizeof (st));
		rc = fstat(fileno(f), &st);
		if (rc != 0) {
			err = errfno("stat", errno, "stat'ing '%s'", cert_path);
			return (err);
		}

		if (S_ISDIR(st.st_mode) || S_ISCHR(st.st_mode) ||
		    S_ISBLK(st.st_mode)
#if defined(S_ISSOCK)
		    || S_ISSOCK(st.st_mode)
#endif
		    ) {
			err = errf("InvalidFileType", NULL, "file '%s' is not "
			    "a regular file", cert_path);
			return (err);
		}

		if (st.st_size < 1) {
			err = errf("EmptyFileError", NULL, "file '%s' is empty",
			    cert_path);
			return (err);
		}
	}

	bio = BIO_new_fp(f, BIO_NOCLOSE);
	VERIFY(bio != NULL);

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL) {
		make_sslerrf(err, "PEM_read_bio_X509_REQ", "parsing %s",
		    (f == stdin) ? "stdin" : cert_path);
		return (err);
	}

	err = ca_revoke_cert(ca, sess, cert);
	if (err != ERRF_OK)
		return (err);

	ca_close_session(sess);
	ca_close(ca);

	return (ERRF_OK);
}

static errf_t *
cmd_revoke_serial(const char *ca_path, const char *serial)
{
	errf_t *err;
	BIGNUM *serbn;
	struct ca *ca;
	struct ca_session *sess;
	int rc;

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	err = ca_open_session(ca, &sess);
	if (err != ERRF_OK)
		return (err);

	err = ensure_authed(ca, sess);
	if (err != ERRF_OK)
		return (err);

	if (strncmp(serial, "0t", 2) == 0) {
		rc = BN_dec2bn(&serbn, &serial[2]);
		if (rc == 0) {
			make_sslerrf(err, "BN_dec2bn", "parsing serial '%s'",
			    serial);
			return (err);
		}
	} else {
		rc = BN_hex2bn(&serbn, serial);
		if (rc == 0) {
			make_sslerrf(err, "BN_hex2bn", "parsing serial '%s'",
			    serial);
			return (err);
		}
	}

	err = ca_revoke_cert_serial(ca, sess, serbn);
	if (err != ERRF_OK)
		return (err);

	ca_close_session(sess);
	ca_close(ca);

	return (ERRF_OK);
}

struct select_tpl_priv {
	struct ca_cert_tpl	*stp_tpl;
};

static struct ca_cert_tpl *
select_tpl(struct ca *ca)
{
	struct question *q;
	struct answer *a;
	struct ca_cert_tpl *tpl;
	struct select_tpl_priv *priv;
	char key = '1';

	qa_term_setup();

	q = calloc(1, sizeof (struct question));
	VERIFY(q != NULL);
	question_printf(q, "-- Select template --\n");
	question_printf(q, "Select a template to use for issuing this "
	    "certificate.\n");

	tpl = ca_cert_tpl_first(ca);
	for (; tpl != NULL; tpl = ca_cert_tpl_next(tpl)) {
		a = make_answer(key++, "%s (%s)", ca_cert_tpl_name(tpl),
		    cert_tpl_name(ca_cert_tpl_tpl(tpl)));
		if (ca_cert_tpl_help(tpl) != NULL)
			answer_printf(a, " [%s]", ca_cert_tpl_help(tpl));
		priv = calloc(1, sizeof (*priv));
		VERIFY(priv != NULL);
		priv->stp_tpl = tpl;
		a->a_priv = priv;
		add_answer(q, a);
		if (key > '9' && key < 'a')
			key = 'a';
	}

	question_prompt(q, &a);
	priv = a->a_priv;
	tpl = priv->stp_tpl;
	question_free(q);
	return (tpl);
}

static errf_t *
cmd_sign_req(const char *ca_path, const char *tpl_name, const char *req_path)
{
	FILE *f = NULL;
	errf_t *err;
	struct stat st;
	X509_REQ *req;
	X509 *cert;
	struct ca *ca;
	struct ca_session *sess;
	struct ca_cert_tpl *tpl;
	struct cert_var_scope *ca_scope, *cert_scope;
	int rc;
	BIO *bio;

	err = ca_open(ca_path, &ca);
	if (err != ERRF_OK)
		return (err);

	if (tpl_name != NULL) {
		tpl = ca_cert_tpl_get(ca, tpl_name);
		if (tpl == NULL) {
			err = errf("TemplateNotFound", NULL, "CA does not contain "
			    "a cert template with name '%s'", tpl_name);
			return (err);
		}
	} else {
		tpl = select_tpl(ca);
	}

	if (req_path == NULL || strcmp(req_path, "-") == 0) {
		f = stdin;
	} else {
		f = fopen(req_path, "r");
		if (f == NULL) {
			err = errfno("fopen", errno, "opening '%s'", req_path);
			return (err);
		}
		bzero(&st, sizeof (st));
		rc = fstat(fileno(f), &st);
		if (rc != 0) {
			err = errfno("stat", errno, "stat'ing '%s'", req_path);
			return (err);
		}

		if (S_ISDIR(st.st_mode) || S_ISCHR(st.st_mode) ||
		    S_ISBLK(st.st_mode)
#if defined(S_ISSOCK)
		    || S_ISSOCK(st.st_mode)
#endif
		    ) {
			err = errf("InvalidFileType", NULL, "file '%s' is not "
			    "a regular file", req_path);
			return (err);
		}

		if (st.st_size < 1) {
			err = errf("EmptyFileError", NULL, "file '%s' is empty",
			    req_path);
			return (err);
		}
	}

	bio = BIO_new_fp(f, BIO_NOCLOSE);
	VERIFY(bio != NULL);

	req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	if (req == NULL) {
		make_sslerrf(err, "PEM_read_bio_X509_REQ", "parsing %s",
		    (f == stdin) ? "stdin" : req_path);
		return (err);
	}

	ca_scope = ca_make_scope(ca, root_scope);
	VERIFY(ca_scope != NULL);

	cert_scope = ca_cert_tpl_make_scope(tpl, ca_scope);
	VERIFY(cert_scope != NULL);

	err = scope_populate_req(cert_scope, req);
	if (err != ERRF_OK)
		return (err);

	err = prompt_scope(cert_scope);
	if (err != ERRF_OK)
		return (err);

	err = ca_open_session(ca, &sess);
	if (err != ERRF_OK)
		return (err);

	err = ensure_authed(ca, sess);
	if (err != ERRF_OK)
		return (err);

	cert = X509_new();
	VERIFY(cert != NULL);

	err = ca_cert_sign_req(sess, tpl, cert_scope, req, cert);
	if (err != ERRF_OK)
		return (err);

	PEM_write_X509(stdout, cert);

	ca_close_session(sess);
	ca_close(ca);

	return (ERRF_OK);
}

static errf_t *
parse_json_scope(const char *buf, size_t len)
{
	enum json_tokener_error jerr;
	struct json_tokener *tok = NULL;
	json_object *robj = NULL;
	json_object_iter iter;
	errf_t *err;

	tok = json_tokener_new();
	if (tok == NULL) {
		err = errfno("json_tokener_new", errno, NULL);
		goto out;
	}

	robj = json_tokener_parse_ex(tok, buf, len + 1);
	if ((jerr = json_tokener_get_error(tok)) != json_tokener_success) {
		err = jtokerrf("json_tokener_parse_ex", jerr);
		goto out;
	}
	VERIFY(robj != NULL);
	if (json_tokener_get_parse_end(tok) < len) {
		err = errf("LengthError", NULL, "JSON object ended after "
		    "%zu bytes, expected %zu", json_tokener_get_parse_end(tok),
		    len);
		goto out;
	}

	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(robj, iter) {
		err = scope_set(root_scope, iter.key,
		    json_object_get_string(iter.val));
		if (err != ERRF_OK) {
			err = errf("JSONError", err, "Input JSON has "
			    "invalid '%s' property", iter.key);
			goto out;
		}
	}

	err = ERRF_OK;

out:
	json_object_put(robj);
	if (tok != NULL)
		json_tokener_free(tok);
	return (err);
}

const char *optstring = "p:D:J:jK";

errf_t *read_text_file(const char *path, char **out, size_t *outlen);

int
main(int argc, char *argv[])
{
	errf_t *err = ERRF_OK;
	extern char *optarg;
	extern int optind;
	int c;
	size_t len;
	char *ptr;
	uint d_level = 0;
	uint K_level = 0;
	const char *ca_path = ".";

	bunyan_init();
	bunyan_set_name("pivy-ca");

	root_scope = scope_new_root();
	VERIFY(root_scope != NULL);

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'D':
			ptr = strchr(optarg, '=');
			if (ptr == NULL) {
				errx(EXIT_BAD_ARGS, "invalid cert var: '%s'",
				    optarg);
			}
			*ptr = '\0';
			err = scope_set(root_scope, optarg, ptr+1);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "error while parsing "
				    "-D arg: %s", optarg);
			}
			break;
		case 'J':
			err = read_text_file(optarg, &ptr, &len);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "while processing "
				    "-j option");
			}
			err = parse_json_scope(ptr, len);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "while processing "
				    "-j option");
			}
			break;
		case 'j':
			output_json = B_TRUE;
			break;
		case 'p':
			ca_path = optarg;
			break;
		case 'K':
			K_level++;
			break;
		case 'd':
			bunyan_set_level(BNY_TRACE);
			if (++d_level > 1)
				piv_full_apdu_debug = B_TRUE;
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

	ctx = piv_open();
	VERIFY(ctx != NULL);

	err = piv_establish_context(ctx, SCARD_SCOPE_SYSTEM);
	if (err && errf_caused_by(err, "ServiceError")) {
		errf_free(err);
	} else if (err) {
		errfx(EXIT_ERROR, err, "failed to initialise libpcsc");
	}

	if (strcmp(op, "setup") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_setup(ca_path);

	} else if (strcmp(op, "shell") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_shell(ca_path, K_level);

	} else if (strcmp(op, "show") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_show(ca_path);

	} else if (strcmp(op, "list-tpl") == 0) {
		const char *tpl_name = NULL;
		if (optind < argc)
			tpl_name = argv[optind++];
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_list_tpl(ca_path, tpl_name);

	} else if (strcmp(op, "sign-config") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_sign_config(ca_path);

	} else if (strcmp(op, "sign-req") == 0) {
		const char *req_path = NULL;
		const char *tpl_name = NULL;

		if (optind < argc)
			req_path = argv[optind++];

		if (optind < argc)
			tpl_name = argv[optind++];

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_sign_req(ca_path, tpl_name, req_path);

	} else if (strcmp(op, "revoke-cert") == 0) {
		const char *cert_path = NULL;

		if (optind < argc)
			cert_path = argv[optind++];

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_revoke_cert(ca_path, cert_path);

	} else if (strcmp(op, "revoke-serial") == 0) {
		const char *serial = NULL;

		if (optind >= argc) {
			warnx("not enough arguments for %s", op);
			usage();
		}
		serial = argv[optind++];

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_revoke_serial(ca_path, serial);

	} else if (strcmp(op, "sign-crl") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_sign_crl(ca_path);

	} else if (strcmp(op, "rotate-pin") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_rotate_pin(ca_path);

	} else {
		warnx("invalid operation '%s'", op);
		usage();
	}

	if (err)
		errfx(1, err, "error occurred while executing '%s'", op);

	return (0);
}

void
cleanup_exit(int i)
{
	exit(i);
}
