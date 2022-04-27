/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2022 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <strings.h>
#include <limits.h>
#include <err.h>
#include <ctype.h>

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

#include <json.h>

#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/authfd.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "errf.h"
#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"
#include "debug.h"
#include "pkinit_asn1.h"
#include "piv-ca.h"

/* We need the piv_cert_comp enum */
#include "piv-internal.h"

struct ca_uri {
	struct ca_uri		*cu_next;
	char			*cu_uri;
};

struct ca_ebox_tpl {
	struct ca_ebox_tpl	*cet_next;
	char			*cet_name;
	struct ebox_tpl		*cet_tpl;
	uint64_t		 cet_refcnt;
};

struct ca {
	char			*ca_base_path;
	char			*ca_slug;
	uint8_t			 ca_guid[16];
	struct sshkey		*ca_cak;
	X509_NAME		*ca_dn;

	boolean_t		 ca_dirty;

	json_object		*ca_vars;

	X509			*ca_cert;
	struct sshkey		*ca_pubkey;

	struct ca_uri		*ca_crls;
	struct ca_uri		*ca_ocsps;

	struct ca_ebox_tpl	*ca_ebox_tpls;

	struct ca_ebox_tpl	*ca_pin_tpl;
	struct ca_ebox_tpl	*ca_backup_tpl;
	struct ca_ebox_tpl	*ca_puk_tpl;
	struct ca_ebox_tpl	*ca_admin_tpl;

	struct ca_session	*ca_sessions;

	struct ca_cert_tpl	*ca_cert_tpls;
	struct ca_token_tpl	*ca_token_tpls;
};

enum ca_session_type {
	CA_SESSION_AGENT,
	CA_SESSION_DIRECT
};
struct ca_session_agent {
	int			 csa_fd;
	struct ssh_identitylist	*csa_idl;
	struct sshkey		*csa_rebox_key;
};
struct ca_session_direct {
	SCARDCONTEXT		 csd_context;
	struct piv_token	*csd_token;
	struct piv_slot		*csd_cakslot;
	struct piv_slot		*csd_slot;
};
struct ca_session {
	struct ca_session	*cs_prev;
	struct ca_session	*cs_next;
	struct ca		*cs_ca;
	enum ca_session_type	 cs_type;
	union {
		struct ca_session_agent		cs_agent;
		struct ca_session_direct 	cs_direct;
	};
};

struct ca_token_tpl {
	struct ca			*ctt_ca;
	struct ca_token_tpl		*ctt_prev;
	struct ca_token_tpl		*ctt_next;
	char				*ctt_name;
	char				*ctt_help;
	enum ca_token_tpl_flags		 ctt_flags;
	enum piv_alg			 ctt_admin_alg;
	struct ca_ebox_tpl		*ctt_puk_tpl;
	struct ca_ebox_tpl		*ctt_backup_tpl;
	struct ca_ebox_tpl		*ctt_admin_tpl;
	json_object			*ctt_vars;
	struct ca_token_slot_tpl	*ctt_slots;

};

struct ca_token_slot_tpl {
	struct ca_token_tpl		*ctst_token_tpl;
	struct ca_token_slot_tpl	*ctst_prev;
	struct ca_token_slot_tpl	*ctst_next;

	enum piv_slotid			 ctst_slotid;
	enum piv_alg			 ctst_alg;
	enum ykpiv_pin_policy		 ctst_pinpol;
	enum ykpiv_touch_policy		 ctst_touchpol;

	const struct cert_tpl		*ctst_tpl;
	enum ca_cert_tpl_flags		 ctst_flags;

	json_object			*ctst_vars;

	struct ca_cert_tpl		*ctst_ctpl_cache;
};

struct ca_cert_tpl {
	struct ca			*cct_ca;
	struct ca_cert_tpl		*cct_next;
	struct ca_cert_tpl		*cct_prev;

	char				*cct_name;
	char				*cct_help;
	enum ca_cert_type		 cct_type;
	enum ca_cert_tpl_flags		 cct_flags;

	const struct cert_tpl		*cct_tpl;
	json_object			*cct_vars;
};

struct ca_new_args {
	char			*cna_init_pin;
	char			*cna_init_puk;

	enum piv_alg		 cna_init_admin_alg;
	uint8_t			*cna_init_admin;
	size_t			 cna_init_admin_len;

	enum piv_alg		 cna_key_alg;
	struct ca_ebox_tpl	*cna_ebox_tpls;
	struct ca_ebox_tpl	*cna_backup_tpl;
	struct ca_ebox_tpl	*cna_pin_tpl;
	struct ca_ebox_tpl	*cna_puk_tpl;

	X509_NAME		*cna_dn;

	struct cert_var_scope	*cna_scope;
};

static errf_t *scope_to_json(struct cert_var_scope *cvs, json_object **robjp);

static errf_t *agent_sign_json(int fd, struct sshkey *pubkey,
    const char *subprop, json_object *obj);
static errf_t *piv_sign_json(struct piv_token *tkn, struct piv_slot *slot,
    const char *subprop, json_object *obj);
static errf_t *verify_json(struct sshkey *pubkey, const char *subprop,
    json_object *obj);

errf_t *read_text_file(const char *path, char **out, size_t *outlen);
errf_t *validate_cstring(const char *buf, size_t len, size_t maxlen);

static struct ca_ebox_tpl *get_ebox_tpl(struct ca_ebox_tpl **, const char *,
    int);

static inline void
set_ca_ebox_ptr(struct ca_ebox_tpl **ptr, struct ca_ebox_tpl *newval)
{
	if (*ptr != NULL)
		(*ptr)->cet_refcnt--;
	*ptr = newval;
	if (newval != NULL)
		newval->cet_refcnt++;
}

static errf_t *
scope_to_json(struct cert_var_scope *cvs, json_object **robjp)
{
	json_object *robj = NULL, *obj;
	struct cert_var *cv;
	errf_t *err;

	robj = json_object_new_object();
	VERIFY(robj != NULL);

	for (cv = cvs->cvs_vars; cv != NULL; cv = cv->cv_next) {
		char *vstr;
		if (cv->cv_value == NULL)
			continue;
		vstr = varval_unparse(cv->cv_value);
		VERIFY(vstr != NULL);
		obj = json_object_new_string(vstr);
		VERIFY(obj != NULL);
		json_object_object_add(robj, cv->cv_name, obj);
	}

	*robjp = robj;
	robj = NULL;
	err = ERRF_OK;

out:
	json_object_put(robj);
	return (err);
}

static enum sshdigest_types
best_sign_alg_for_key(struct sshkey *pubkey)
{
	switch (pubkey->type) {
	case KEY_RSA:
		return (SSH_DIGEST_SHA256);
	case KEY_ECDSA:
		switch (sshkey_size(pubkey)) {
		case 256:
			return (SSH_DIGEST_SHA256);
		case 384:
			return (SSH_DIGEST_SHA384);
		default:
			return (SSH_DIGEST_SHA512);
		}
	default:
		return (SSH_DIGEST_SHA256);
	}
}

static errf_t *
agent_sign_json(int fd, struct sshkey *pubkey, const char *subprop,
    json_object *obj)
{
	int rc;
	errf_t *err;
	json_object *sigprop = NULL, *sigsubprop;
	char *sigb64 = NULL;
	struct sshbuf *sigbuf = NULL, *tbsbuf = NULL;
	uint8_t *sig = NULL;
	size_t siglen;
	const char *alg = NULL;
	const char *tmp;

	if (pubkey->type == KEY_RSA)
		alg = "rsa-sha2-256";

	tbsbuf = sshbuf_new();
	if (tbsbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}

	sigprop = json_object_object_get(obj, "signature");
	if (sigprop == NULL) {
		if (subprop != NULL)
			sigprop = json_object_new_object();
		else
			sigprop = json_object_new_string("");
	} else {
		VERIFY(json_object_is_type(sigprop, json_type_object));
		json_object_get(sigprop);
		json_object_object_del(obj, "signature");
	}
	VERIFY(sigprop != NULL);

	if (subprop == NULL) {
		sigsubprop = sigprop;
	} else {
		sigsubprop = json_object_object_get(sigprop, subprop);
		if (sigsubprop == NULL) {
			sigsubprop = json_object_new_string("");
			VERIFY(sigsubprop != NULL);
			rc = json_object_object_add(sigprop, subprop,
			    sigsubprop);
			if (rc != 0) {
				err = jsonerrf("json_object_object_add");
				goto out;
			}
		}
		VERIFY(json_object_is_type(sigsubprop, json_type_string));
	}

	tmp = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);

	if ((rc = sshbuf_put_cstring8(tbsbuf, "piv-ca-json-signature")) ||
	    (rc = sshbuf_put_cstring(tbsbuf, tmp))) {
		err = ssherrf("sshbuf_put_cstring", rc);
		goto out;
	}

	rc = ssh_agent_sign(fd, pubkey, &sig, &siglen, sshbuf_ptr(tbsbuf),
	    sshbuf_len(tbsbuf), alg, 0);
	if (rc != 0) {
		err = ssherrf("ssh_agent_sign", rc);
		goto out;
	}

	sigbuf = sshbuf_from(sig, siglen);
	if (sigbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}

	sigb64 = sshbuf_dtob64_string(sigbuf, 0);
	if (sigb64 == NULL) {
		err = errf("ConversionError", NULL, "Failed to convert "
		    "signature value to base64");
		goto out;
	}

	rc = json_object_set_string(sigsubprop, sigb64);
	if (rc != 1) {
		err = jsonerrf("json_object_set_string");
		goto out;
	}

	rc = json_object_object_add(obj, "signature", sigprop);
	if (rc != 0) {
		err = jsonerrf("json_object_object_add");
		goto out;
	}
	/* json_object_object_add takes ownership */
	sigprop = NULL;

	err = ERRF_OK;

out:
	free(sigb64);
	sshbuf_free(sigbuf);
	free(sig);
	sshbuf_free(tbsbuf);
	json_object_put(sigprop);
	return (err);
}

static errf_t *
piv_sign_json(struct piv_token *tkn, struct piv_slot *slot,
    const char *subprop, json_object *obj)
{
	int rc;
	errf_t *err;
	json_object *sigprop = NULL, *sigsubprop;
	char *sigb64 = NULL;
	struct sshbuf *sigbuf = NULL, *tbsbuf = NULL;
	enum sshdigest_types hashalg;
	struct sshkey *pubkey;
	uint8_t *sig = NULL;
	size_t siglen;
	const char *tmp;

	pubkey = piv_slot_pubkey(slot);
	if (pubkey == NULL) {
		err = errf("NoPubKey", NULL, "Slot %02x has no public key",
		    piv_slot_id(slot));
		goto out;
	}

	hashalg = best_sign_alg_for_key(pubkey);

	tbsbuf = sshbuf_new();
	if (tbsbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}

	sigprop = json_object_object_get(obj, "signature");
	if (sigprop == NULL) {
		if (subprop != NULL)
			sigprop = json_object_new_object();
		else
			sigprop = json_object_new_string("");
	} else {
		VERIFY(json_object_is_type(sigprop, json_type_object));
		json_object_get(sigprop);
		json_object_object_del(obj, "signature");
	}
	VERIFY(sigprop != NULL);

	if (subprop == NULL) {
		sigsubprop = sigprop;
	} else {
		sigsubprop = json_object_object_get(sigprop, subprop);
		if (sigsubprop == NULL) {
			sigsubprop = json_object_new_string("");
			VERIFY(sigsubprop != NULL);
			rc = json_object_object_add(sigprop, subprop,
			    sigsubprop);
			if (rc != 0) {
				err = jsonerrf("json_object_object_add");
				goto out;
			}
		}
		VERIFY(json_object_is_type(sigsubprop, json_type_string));
	}

	tmp = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);

	if ((rc = sshbuf_put_cstring8(tbsbuf, "piv-ca-json-signature")) ||
	    (rc = sshbuf_put_cstring(tbsbuf, tmp))) {
		err = ssherrf("sshbuf_put_cstring", rc);
		goto out;
	}

	err = piv_sign(tkn, slot, sshbuf_ptr(tbsbuf), sshbuf_len(tbsbuf),
	    &hashalg, &sig, &siglen);
	if (err != ERRF_OK)
		goto out;

	sigbuf = sshbuf_new();
	if (sigbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}

	rc = sshkey_sig_from_asn1(pubkey, hashalg, sig, siglen, sigbuf);
	if (rc != 0) {
		err = errf("NotSupportedError",
		    ssherrf("sshkey_sig_from_asn1", rc),
		    "PIV device '%s' returned an unsupported signature format",
		    piv_token_rdrname(tkn));
		goto out;
	}

	sigb64 = sshbuf_dtob64_string(sigbuf, 0);
	if (sigb64 == NULL) {
		err = errf("ConversionError", NULL, "Failed to convert "
		    "signature value to base64");
		goto out;
	}

	rc = json_object_set_string(sigsubprop, sigb64);
	if (rc != 1) {
		err = jsonerrf("json_object_set_string");
		goto out;
	}

	rc = json_object_object_add(obj, "signature", sigprop);
	if (rc != 0) {
		err = jsonerrf("json_object_object_add");
		goto out;
	}
	/* json_object_object_add takes ownership */
	sigprop = NULL;

	err = ERRF_OK;

out:
	free(sig);
	free(sigb64);
	sshbuf_free(sigbuf);
	sshbuf_free(tbsbuf);
	json_object_put(sigprop);
	return (err);
}

static errf_t *
verify_json(struct sshkey *pubkey, const char *subprop, json_object *obj)
{
	int rc;
	const char *tmp;
	json_object *sigprop = NULL, *sigsubprop;
	errf_t *err;
	struct sshbuf *sigbuf = NULL, *tbsbuf = NULL;

	sigprop = json_object_object_get(obj, "signature");
	if (sigprop == NULL) {
		err = errf("JSONSignatureError", NULL, "No 'signature' "
		    "property found in JSON object");
		goto out;
	}
	json_object_get(sigprop);

	if (subprop == NULL) {
		sigsubprop = sigprop;
	} else {
		sigsubprop = json_object_object_get(sigprop, subprop);
		if (sigsubprop == NULL) {
			err = errf("JSONSignatureError", NULL, "No '%s' sub-"
			    "property found in signature of JSON object",
			    subprop);
			goto out;
		}
	}

	tmp = json_object_get_string(sigsubprop);
	if (tmp == NULL) {
		err = errf("JSONSignatureError", NULL, "Property 'signature' "
		    "is null");
		goto out;
	}

	sigbuf = sshbuf_new();
	if (sigbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}
	rc = sshbuf_b64tod(sigbuf, tmp);
	if (rc != 0) {
		err = ssherrf("sshbuf_b64tod", rc);
		goto out;
	}

	json_object_object_del(obj, "signature");
	tmp = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);

	tbsbuf = sshbuf_new();
	if (tbsbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}
	if ((rc = sshbuf_put_cstring8(tbsbuf, "piv-ca-json-signature")) ||
	    (rc = sshbuf_put_cstring(tbsbuf, tmp))) {
		err = ssherrf("sshbuf_put_cstring", rc);
		goto out;
	}

	rc = sshkey_verify(pubkey, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf),
	    sshbuf_ptr(tbsbuf), sshbuf_len(tbsbuf), NULL, 0, NULL);
	if (rc != 0) {
		const char *v = getenv("PIVY_CA_NO_VERIFY_SIGNATURES");
		if (v == NULL ||
		    strcasecmp(v, "yes-i-really-want-no-security") != 0) {
			err = ssherrf("sshkey_verify", rc);
			goto out;
		}
	}

	rc = json_object_object_add(obj, "signature", sigprop);
	if (rc != 0) {
		err = jsonerrf("json_object_object_add");
		goto out;
	}
	/* json_object_object_add takes ownership */
	sigprop = NULL;

	err = ERRF_OK;
out:
	sshbuf_free(sigbuf);
	sshbuf_free(tbsbuf);
	json_object_put(sigprop);
	return (err);
}

static void
ca_ebox_tpl_free(struct ca_ebox_tpl *cet)
{
	free(cet->cet_name);
	ebox_tpl_free(cet->cet_tpl);
	free(cet);
}

void
ca_close(struct ca *ca)
{
	struct ca_uri *uri, *nuri;
	struct ca_cert_tpl *ctpl, *nctpl;
	struct ca_token_tpl *ttpl, *nttpl;
	struct ca_ebox_tpl *cet, *ncet;

	if (ca == NULL)
		return;

	VERIFY(!ca->ca_dirty);
	VERIFY(ca->ca_sessions == NULL);

	free(ca->ca_base_path);
	free(ca->ca_slug);
	sshkey_free(ca->ca_cak);
	X509_NAME_free(ca->ca_dn);
	json_object_put(ca->ca_vars);
	X509_free(ca->ca_cert);
	sshkey_free(ca->ca_pubkey);
	for (cet = ca->ca_ebox_tpls; cet != NULL; cet = ncet) {
		ncet = cet->cet_next;
		ca_ebox_tpl_free(cet);
	}
	for (uri = ca->ca_crls; uri != NULL; uri = nuri) {
		nuri = uri->cu_next;
		free(uri->cu_uri);
		free(uri);
	}
	for (uri = ca->ca_ocsps; uri != NULL; uri = nuri) {
		nuri = uri->cu_next;
		free(uri->cu_uri);
		free(uri);
	}
	for (ctpl = ca->ca_cert_tpls; ctpl != NULL; ctpl = nctpl) {
		nctpl = ctpl->cct_next;
		ctpl->cct_next = NULL;
		ctpl->cct_prev = NULL;
		ca_cert_tpl_free(ctpl);
	}
	for (ttpl = ca->ca_token_tpls; ttpl != NULL; ttpl = nttpl) {
		nttpl = ttpl->ctt_next;
		ttpl->ctt_next = NULL;
		ttpl->ctt_prev = NULL;
		ca_token_tpl_free(ttpl);
	}
	free(ca);
}

static struct ca_ebox_tpl *
get_ebox_tpl(struct ca_ebox_tpl **head, const char *tplname, int create)
{
	struct ca_ebox_tpl *cet, *tcet = NULL;

	for (cet = *head; cet != NULL; cet = cet->cet_next) {
		if (strcmp(cet->cet_name, tplname) == 0) {
			tcet = cet;
			break;
		}
	}
	if (tcet == NULL && create) {
		tcet = calloc(1, sizeof (struct ca_ebox_tpl));
		VERIFY(tcet != NULL);
		tcet->cet_name = strdup(tplname);
		VERIFY(tcet->cet_name != NULL);
		tcet->cet_next = *head;
		*head = tcet;
	}

	return (tcet);
}

static errf_t *
parse_ebox_spec(struct ca *ca, const char *name, json_object *obj)
{
	struct ca_ebox_tpl *tcet = NULL;
	const char *tplname;
	errf_t *err = NULL;
	json_object *prop;

	prop = json_object_object_get(obj, "template");
	if (prop == NULL) {
		err = errf("ParseError", NULL, "Failed to parse ebox "
		    "template '%s': no 'template' property", name);
		return (err);
	}

	tplname = json_object_get_string(prop);
	if (tplname == NULL) {
		err = jsonerrf("json_object_get_string");
		err = errf("ParseError", err, "Failed to parse ebox "
		    "template '%s'", name);
		return (err);
	}

	tcet = get_ebox_tpl(&ca->ca_ebox_tpls, tplname, 0);
	if (tcet == NULL) {
		err = errf("ParseError", err, "Failed to parse ebox "
		    "template '%s': invalid ebox tpl name '%s'", name,
		    tplname);
		return (err);
	}

	if (strcmp(name, "pin") == 0)
		set_ca_ebox_ptr(&ca->ca_pin_tpl, tcet);
	else if (strcmp(name, "backup") == 0)
		set_ca_ebox_ptr(&ca->ca_backup_tpl, tcet);
	else if (strcmp(name, "puk") == 0)
		set_ca_ebox_ptr(&ca->ca_puk_tpl, tcet);
	else if (strcmp(name, "admin") == 0)
		set_ca_ebox_ptr(&ca->ca_admin_tpl, tcet);
	else {
		return (errf("InvalidProperty", NULL, "Unknown ebox "
		    "name '%s'", name));
	}

	return (ERRF_OK);
}

static errf_t *
parse_ebox_template(struct ca *ca, const char *name, json_object *obj)
{
	const char *b64;
	struct ca_ebox_tpl *cet;
	struct sshbuf *buf;
	int rc;
	errf_t *err;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	cet = calloc(1, sizeof (struct ca_ebox_tpl));
	VERIFY(cet != NULL);

	cet->cet_name = strdup(name);

	b64 = json_object_get_string(obj);
	rc = sshbuf_b64tod(buf, b64);
	if (rc != 0) {
		err = ssherrf("sshbuf_b64tod", rc);
		err = errf("ParseError", err, "Failed to parse ebox "
		    "template '%s'", name);
		sshbuf_free(buf);
		return (err);
	}
	err = sshbuf_get_ebox_tpl(buf, &cet->cet_tpl);
	if (err != ERRF_OK) {
		err = errf("ParseError", err, "Failed to parse ebox "
		    "template '%s'", name);
		sshbuf_free(buf);
		return (err);
	}
	sshbuf_free(buf);

	cet->cet_next = ca->ca_ebox_tpls;
	ca->ca_ebox_tpls = cet;

	return (ERRF_OK);
}

void
ca_cert_tpl_free(struct ca_cert_tpl *tpl)
{
	if (tpl == NULL)
		return;
	VERIFY(tpl->cct_next == NULL);
	VERIFY(tpl->cct_prev == NULL);
	free(tpl->cct_help);
	free(tpl->cct_name);
	if (tpl->cct_vars != NULL)
		json_object_put(tpl->cct_vars);
	free(tpl);
}

static errf_t *
parse_cert_template(struct ca *ca, const char *name, json_object *robj)
{
	struct ca_cert_tpl *tpl;
	json_object *obj;

	tpl = calloc(1, sizeof (struct ca_cert_tpl));
	VERIFY(tpl != NULL);

	tpl->cct_name = strdup(name);
	VERIFY(tpl->cct_name != NULL);

	tpl->cct_type = CA_CERT_OTHER;

	obj = json_object_object_get(robj, "help");
	if (obj != NULL)
		tpl->cct_help = strdup(json_object_get_string(obj));

	obj = json_object_object_get(robj, "self_signed");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->cct_flags |= CCTF_SELF_SIGNED;
	obj = json_object_object_get(robj, "allow_reqs");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->cct_flags |= CCTF_ALLOW_REQS;
	obj = json_object_object_get(robj, "copy_dn");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->cct_flags |= CCTF_COPY_DN;
	obj = json_object_object_get(robj, "copy_kp");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->cct_flags |= CCTF_COPY_KP;
	obj = json_object_object_get(robj, "copy_san");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->cct_flags |= CCTF_COPY_SAN;
	obj = json_object_object_get(robj, "copy_other_exts");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->cct_flags |= CCTF_COPY_OTHER_EXTS;

	obj = json_object_object_get(robj, "template");
	if (obj == NULL) {
		ca_cert_tpl_free(tpl);
		return (errf("MissingProperty", NULL, "Cert template '%s' is "
		    "missing 'template' property", name));
	}
	tpl->cct_tpl = cert_tpl_find(json_object_get_string(obj));
	if (tpl->cct_tpl == NULL) {
		ca_cert_tpl_free(tpl);
		return (errf("InvalidProperty", NULL, "Cert template '%s' uses "
		    "unknown base template '%s'", name,
		    json_object_get_string(obj)));
	}

	tpl->cct_vars = json_object_object_get(robj, "variables");
	if (tpl->cct_vars != NULL)
		json_object_get(tpl->cct_vars);

	tpl->cct_next = ca->ca_cert_tpls;
	if (ca->ca_cert_tpls != NULL)
		ca->ca_cert_tpls->cct_prev = tpl;
	ca->ca_cert_tpls = tpl;

	return (ERRF_OK);
}

void
ca_token_tpl_free(struct ca_token_tpl *tpl)
{
	struct ca_token_slot_tpl *sl, *nsl;
	if (tpl == NULL)
		return;
	VERIFY(tpl->ctt_next == NULL);
	VERIFY(tpl->ctt_prev == NULL);
	free(tpl->ctt_help);
	free(tpl->ctt_name);
	if (tpl->ctt_vars != NULL)
		json_object_put(tpl->ctt_vars);
	for (sl = tpl->ctt_slots; sl != NULL; sl = nsl) {
		nsl = sl->ctst_next;
		sl->ctst_next = NULL;
		sl->ctst_prev = NULL;
		ca_token_slot_tpl_free(sl);
	}
	free(tpl);
}

void
ca_token_slot_tpl_free(struct ca_token_slot_tpl *tpl)
{
	if (tpl == NULL)
		return;
	VERIFY(tpl->ctst_prev == NULL);
	VERIFY(tpl->ctst_next == NULL);
	if (tpl->ctst_vars != NULL)
		json_object_put(tpl->ctst_vars);
	ca_cert_tpl_free(tpl->ctst_ctpl_cache);
	free(tpl);
}

static errf_t *
parse_token_slot_template(struct ca_token_tpl *ctt, enum piv_slotid slotid,
    json_object *robj)
{
	struct ca_token_slot_tpl *tpl;
	errf_t *err;
	json_object *obj;

	tpl = calloc(1, sizeof (struct ca_token_slot_tpl));
	VERIFY(tpl != NULL);

	tpl->ctst_slotid = slotid;
	tpl->ctst_token_tpl = ctt;

	obj = json_object_object_get(robj, "algorithm");
	if (obj == NULL) {
		ca_token_slot_tpl_free(tpl);
		return (errf("MissingProperty", NULL, "Token slot template "
		    "'%s'/%02x is missing 'algorithm' property", ctt->ctt_name,
		    slotid));
	}
	err = piv_alg_from_string(json_object_get_string(obj), &tpl->ctst_alg);
	if (err != ERRF_OK) {
		ca_token_slot_tpl_free(tpl);
		return (errf("MissingProperty", NULL, "Token slot template "
		    "'%s'/%02x has invalid 'algorithm' property", ctt->ctt_name,
		    slotid));
	}

	tpl->ctst_pinpol = YKPIV_PIN_DEFAULT;
	tpl->ctst_touchpol = YKPIV_TOUCH_DEFAULT;

	obj = json_object_object_get(robj, "pin_policy");
	if (obj != NULL) {
		const char *v = json_object_get_string(obj);
		if (strcmp(v, "default") == 0)
			tpl->ctst_pinpol = YKPIV_PIN_DEFAULT;
		else if (strcmp(v, "never") == 0)
			tpl->ctst_pinpol = YKPIV_PIN_NEVER;
		else if (strcmp(v, "once") == 0)
			tpl->ctst_pinpol = YKPIV_PIN_ONCE;
		else if (strcmp(v, "always") == 0)
			tpl->ctst_pinpol = YKPIV_PIN_ALWAYS;
		else {
			ca_token_slot_tpl_free(tpl);
			return (errf("MissingProperty", NULL, "Token slot "
			    "template '%s'/%02x has invalid 'pin_policy' "
			    "property: '%s'", ctt->ctt_name, slotid, v));
		}
	}

	obj = json_object_object_get(robj, "touch_policy");
	if (obj != NULL) {
		const char *v = json_object_get_string(obj);
		if (strcmp(v, "default") == 0)
			tpl->ctst_touchpol = YKPIV_TOUCH_DEFAULT;
		else if (strcmp(v, "never") == 0)
			tpl->ctst_touchpol = YKPIV_TOUCH_NEVER;
		else if (strcmp(v, "cached") == 0)
			tpl->ctst_touchpol = YKPIV_TOUCH_CACHED;
		else if (strcmp(v, "always") == 0)
			tpl->ctst_touchpol = YKPIV_TOUCH_ALWAYS;
		else {
			ca_token_slot_tpl_free(tpl);
			return (errf("MissingProperty", NULL, "Token slot "
			    "template '%s'/%02x has invalid 'touch_policy' "
			    "property: '%s'", ctt->ctt_name, slotid, v));
		}
	}

	obj = json_object_object_get(robj, "template");
	if (obj == NULL) {
		ca_token_slot_tpl_free(tpl);
		return (errf("MissingProperty", NULL, "Token slot template "
		    "'%s'/%02x is missing 'template' property", ctt->ctt_name,
		    slotid));
	}
	tpl->ctst_tpl = cert_tpl_find(json_object_get_string(obj));
	if (tpl->ctst_tpl == NULL) {
		ca_token_slot_tpl_free(tpl);
		return (errf("InvalidProperty", NULL, "Token slot template "
		    "'%s'/%02x uses unknown base template '%s'", ctt->ctt_name,
		    slotid, json_object_get_string(obj)));
	}

	obj = json_object_object_get(robj, "self_signed");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctst_flags |= CCTF_SELF_SIGNED;
	obj = json_object_object_get(robj, "key_backup");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctst_flags |= CCTF_KEY_BACKUP;
	obj = json_object_object_get(robj, "host_keygen");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctst_flags |= CCTF_HOST_KEYGEN;

	tpl->ctst_vars = json_object_object_get(robj, "variables");
	if (tpl->ctst_vars != NULL)
		json_object_get(tpl->ctst_vars);

	tpl->ctst_next = ctt->ctt_slots;
	if (ctt->ctt_slots != NULL)
		ctt->ctt_slots->ctst_prev = tpl;
	ctt->ctt_slots = tpl;

	return (ERRF_OK);
}

static errf_t *
parse_token_template(struct ca *ca, const char *name, json_object *robj)
{
	struct ca_token_tpl *tpl;
	errf_t *err;
	json_object *obj;
	json_object_iter iter;

	tpl = calloc(1, sizeof (struct ca_token_tpl));
	VERIFY(tpl != NULL);

	tpl->ctt_name = strdup(name);
	VERIFY(tpl->ctt_name != NULL);

	obj = json_object_object_get(robj, "help");
	if (obj != NULL)
		tpl->ctt_help = strdup(json_object_get_string(obj));

	obj = json_object_object_get(robj, "randomize_puk");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctt_flags |= CTTF_PUK_RAND;
	obj = json_object_object_get(robj, "randomize_admin_key");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctt_flags |= CTTF_ADMIN_KEY_RAND;
	obj = json_object_object_get(robj, "admin_key_in_pinfo");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctt_flags |= CTTF_ADMIN_KEY_PINFO;
	obj = json_object_object_get(robj, "sign_chuid");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctt_flags |= CTTF_SIGN_CHUID;
	obj = json_object_object_get(robj, "pinfo");
	if (obj != NULL && json_object_get_boolean(obj))
		tpl->ctt_flags |= CTTF_PINFO;

	tpl->ctt_admin_alg = PIV_ALG_3DES;
	obj = json_object_object_get(robj, "admin_key_algorithm");
	if (obj != NULL) {
		const char *algstr = json_object_get_string(obj);
		err = piv_alg_from_string(algstr, &tpl->ctt_admin_alg);
		if (err != ERRF_OK) {
			ca_token_tpl_free(tpl);
			return (errf("InvalidProperty", err, "Token template "
			    "'%s' specifies unknown admin key algo", name));
		}
	}

	obj = json_object_object_get(robj, "slots");
	if (obj == NULL) {
		ca_token_tpl_free(tpl);
		return (errf("MissingProperty", NULL, "Token template '%s' is "
		    "missing 'slots' property", name));
	}
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		enum piv_slotid slotid;
		err = piv_slotid_from_string(iter.key, &slotid);
		if (err != ERRF_OK) {
			ca_token_tpl_free(tpl);
			return (errf("InvalidProperty", err, "Token template "
			    "'%s' has invalid slot: '%s'", name, iter.key));
		}
		err = parse_token_slot_template(tpl, slotid, iter.val);
		if (err != ERRF_OK) {
			ca_token_tpl_free(tpl);
			return (errf("InvalidProperty", err, "Token template "
			    "'%s' has invalid slot: '%s'", name, iter.key));
		}
	}

	set_ca_ebox_ptr(&tpl->ctt_puk_tpl, ca->ca_puk_tpl);
	set_ca_ebox_ptr(&tpl->ctt_backup_tpl, ca->ca_backup_tpl);
	set_ca_ebox_ptr(&tpl->ctt_admin_tpl, ca->ca_admin_tpl);

	obj = json_object_object_get(robj, "eboxes");
	if (obj != NULL) {
		bzero(&iter, sizeof (iter));
		json_object_object_foreachC(obj, iter) {
			const char *tplname;
			struct ca_ebox_tpl *tcet = NULL;

			tplname = json_object_get_string(iter.val);
			tcet = get_ebox_tpl(&ca->ca_ebox_tpls, tplname, 0);
			if (tcet == NULL) {
				ca_token_tpl_free(tpl);
				return (errf("InvalidProperty", err, "Token "
				    "template '%s' has invalid ebox spec: "
				    "'%s' = '%s'", name, iter.key, tplname));
			}

			if (strcmp(iter.key, "puk") == 0)
				set_ca_ebox_ptr(&tpl->ctt_puk_tpl, tcet);
			else if (strcmp(iter.key, "backup") == 0)
				set_ca_ebox_ptr(&tpl->ctt_backup_tpl, tcet);
			else if (strcmp(iter.key, "admin") == 0)
				set_ca_ebox_ptr(&tpl->ctt_admin_tpl, tcet);
			else {
				ca_token_tpl_free(tpl);
				return (errf("InvalidProperty", err, "Token "
				    "template '%s' has invalid ebox spec: "
				    "'%s'", name, iter.key));
			}
		}
	}

	tpl->ctt_vars = json_object_object_get(robj, "variables");
	if (tpl->ctt_vars != NULL)
		json_object_get(tpl->ctt_vars);

	tpl->ctt_next = ca->ca_token_tpls;
	if (ca->ca_token_tpls != NULL)
		ca->ca_token_tpls->ctt_prev = tpl;
	ca->ca_token_tpls = tpl;

	return (ERRF_OK);
}

static void
ca_recalc_slug(struct ca *ca)
{
	struct sshbuf *buf;
	X509_NAME_ENTRY *ent;
	ASN1_OBJECT *obj;
	ASN1_STRING *val;
	int nid;
	uint i, j, max;
	const unsigned char *p;
	int run = 0;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	max = X509_NAME_entry_count(ca->ca_dn);
	for (i = 0; i < max; ++i) {
		ent = X509_NAME_get_entry(ca->ca_dn, i);

		obj = X509_NAME_ENTRY_get_object(ent);
		val = X509_NAME_ENTRY_get_data(ent);

		nid = OBJ_obj2nid(obj);
		if (nid == NID_commonName) {
			p = ASN1_STRING_get0_data(val);
			for (j = 0; j < ASN1_STRING_length(val); ++j) {
				char c = p[j];
				if ((c >= 'a' && c <= 'z') ||
				    (c >= 'A' && c <= 'Z') ||
				    (c >= '0' && c <= '9')) {
					run = 0;
					VERIFY0(sshbuf_put_u8(buf, c));
					continue;
				}
				if (run)
					continue;
				run = 1;
				VERIFY0(sshbuf_put_u8(buf, '-'));
			}
		}
	}

	if (sshbuf_len(buf) < 1) {
		VERIFY0(sshbuf_put(buf, "CA", 2));
	}

	ca->ca_slug = sshbuf_dup_string(buf);

	sshbuf_free(buf);
}

static errf_t *
read_uri_array(json_object *array, struct ca_uri **head)
{
	json_object *obj;
	size_t len, i;
	struct ca_uri *u;

	len = json_object_array_length(array);
	for (i = len - 1; i < len; --i) {
		obj = json_object_array_get_idx(array, i);
		u = calloc(1, sizeof (struct ca_uri));
		if (u == NULL)
			return (errfno("calloc", errno, NULL));
		u->cu_uri = strdup(json_object_get_string(obj));
		u->cu_next = *head;
		*head = u;
	}

	return (ERRF_OK);
}

errf_t *
ca_set_ebox_tpl(struct ca *ca, enum ca_ebox_type type, const char *tplname)
{
	struct ca_ebox_tpl *cet;
	struct ca_ebox_tpl **ptr;

	cet = get_ebox_tpl(&ca->ca_ebox_tpls, tplname, 0);
	if (cet == NULL || cet->cet_tpl == NULL) {
		return (errf("InvalidTemplateName", NULL, "Invalid template "
		   "name: '%s'", tplname));
	}

	switch (type) {
	case CA_EBOX_PIN:
		ptr = &ca->ca_pin_tpl;
		break;
	case CA_EBOX_PUK:
		ptr = &ca->ca_puk_tpl;
		break;
	case CA_EBOX_KEY_BACKUP:
		ptr = &ca->ca_backup_tpl;
		break;
	case CA_EBOX_ADMIN_KEY:
		ptr = &ca->ca_admin_tpl;
		break;
	}
	set_ca_ebox_ptr(ptr, cet);

	return (ERRF_OK);
}

errf_t *
ca_set_ebox_tpl_name(struct ca *ca, const char *tplname, struct ebox_tpl *tpl)
{
	struct ca_ebox_tpl *cet;

	cet = get_ebox_tpl(&ca->ca_ebox_tpls, tplname, 1);
	ebox_tpl_free(cet->cet_tpl);
	cet->cet_tpl = ebox_tpl_clone(tpl);
	VERIFY(cet->cet_tpl != NULL);

	return (ERRF_OK);
}

struct ca_new_args *
cana_new(void)
{
	struct ca_new_args *cna;

	cna = calloc(1, sizeof (struct ca_new_args));
	if (cna == NULL)
		return (cna);
	cna->cna_key_alg = PIV_ALG_RSA2048;
	cna->cna_scope = scope_new_root();

	return (cna);
}

void
cana_free(struct ca_new_args *cna)
{
	struct ca_ebox_tpl *cet, *ncet;
	if (cna == NULL)
		return;
	if (cna->cna_init_pin != NULL)
		freezero(cna->cna_init_pin, strlen(cna->cna_init_pin));
	if (cna->cna_init_puk != NULL)
		freezero(cna->cna_init_puk, strlen(cna->cna_init_puk));
	freezero(cna->cna_init_admin, cna->cna_init_admin_len);

	for (cet = cna->cna_ebox_tpls; cet != NULL; cet = ncet) {
		ncet = cet->cet_next;
		ca_ebox_tpl_free(cet);
	}

	X509_NAME_free(cna->cna_dn);

	free(cna);
}

void
cana_initial_pin(struct ca_new_args *cna, const char *pin)
{
	size_t len;
	if (cna->cna_init_pin != NULL)
		freezero(cna->cna_init_pin, strlen(cna->cna_init_pin));
	len = strlen(pin) + 1;
	cna->cna_init_pin = calloc_conceal(1, len);
	VERIFY(cna->cna_init_pin != NULL);
	strlcpy(cna->cna_init_pin, pin, len);
}

void
cana_initial_puk(struct ca_new_args *cna, const char *puk)
{
	size_t len;
	if (cna->cna_init_puk != NULL)
		freezero(cna->cna_init_puk, strlen(cna->cna_init_puk));
	len = strlen(puk) + 1;
	cna->cna_init_puk = calloc_conceal(1, len);
	VERIFY(cna->cna_init_puk != NULL);
	strlcpy(cna->cna_init_puk, puk, len);
}

void
cana_initial_admin_key(struct ca_new_args *cna, enum piv_alg alg, uint8_t *key,
    size_t keylen)
{
	freezero(cna->cna_init_admin, cna->cna_init_admin_len);
	cna->cna_init_admin_alg = alg;
	cna->cna_init_admin_len = keylen;
	cna->cna_init_admin = malloc_conceal(keylen);
	VERIFY(cna->cna_init_admin != NULL);
	bcopy(key, cna->cna_init_admin, keylen);
}

void
cana_key_alg(struct ca_new_args *cna, enum piv_alg alg)
{
	cna->cna_key_alg = alg;
}

void
cana_dn(struct ca_new_args *cna, X509_NAME *name)
{
	X509_NAME_free(cna->cna_dn);
	cna->cna_dn = X509_NAME_dup(name);
	VERIFY(cna->cna_dn != NULL);
}

void
cana_scope(struct ca_new_args *cna, struct cert_var_scope *scope)
{
	const struct cert_tpl *tpl = cert_tpl_find("ca");
	VERIFY(tpl != NULL);
	cna->cna_scope = scope_new_for_tpl(scope, tpl);
	VERIFY(cna->cna_scope != NULL);
}

void
cana_backup_tpl(struct ca_new_args *cna, const char *tplname,
    struct ebox_tpl *tpl)
{
	struct ca_ebox_tpl *cet;

	cet = get_ebox_tpl(&cna->cna_ebox_tpls, tplname, 1);
	if (cet->cet_tpl == NULL) {
		cet->cet_tpl = ebox_tpl_clone(tpl);
		VERIFY(cet->cet_tpl != NULL);
	}
	set_ca_ebox_ptr(&cna->cna_backup_tpl, cet);
}

void
cana_pin_tpl(struct ca_new_args *cna, const char *tplname,
    struct ebox_tpl *tpl)
{
	struct ca_ebox_tpl *cet;

	cet = get_ebox_tpl(&cna->cna_ebox_tpls, tplname, 1);
	if (cet->cet_tpl == NULL) {
		cet->cet_tpl = ebox_tpl_clone(tpl);
		VERIFY(cet->cet_tpl != NULL);
	}
	set_ca_ebox_ptr(&cna->cna_pin_tpl, cet);
}

void
cana_puk_tpl(struct ca_new_args *cna, const char *tplname,
    struct ebox_tpl *tpl)
{
	struct ca_ebox_tpl *cet;

	cet = get_ebox_tpl(&cna->cna_ebox_tpls, tplname, 1);
	if (cet->cet_tpl == NULL) {
		cet->cet_tpl = ebox_tpl_clone(tpl);
		VERIFY(cet->cet_tpl != NULL);
	}
	set_ca_ebox_ptr(&cna->cna_puk_tpl, cet);
}

char *
generate_pin(void)
{
	char *out;
	uint i;
	out = calloc_conceal(9, 1);
	if (out == NULL)
		return (NULL);
	for (i = 0; i < 8; ++i)
		out[i] = '0' + arc4random_uniform(10);
	return (out);
}

static errf_t *
ca_write_key_backup(struct ca *ca, struct sshkey *privkey)
{
	struct sshbuf *kbuf = NULL, *buf = NULL;
	struct ebox_stream *kbackup = NULL;
	struct ebox_stream_chunk *chunk = NULL;
	size_t done;
	int rc;
	FILE *baf = NULL;
	char fname[PATH_MAX];
	errf_t *err;

	buf = sshbuf_new();
	if (buf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	kbuf = sshbuf_new();
	if (kbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	err = ebox_stream_new(ca->ca_backup_tpl->cet_tpl, &kbackup);
	if (err != ERRF_OK) {
		goto out;
	}

	rc = sshkey_private_serialize(privkey, kbuf);
	if (rc != 0) {
		err = ssherrf("sshkey_private_serialize", rc);
		goto out;
	}

	err = ebox_stream_chunk_new(kbackup, sshbuf_ptr(kbuf), sshbuf_len(kbuf),
	    0, &chunk);
	if (err != ERRF_OK) {
		goto out;
	}
	err = ebox_stream_encrypt_chunk(chunk);
	if (err != ERRF_OK) {
		goto out;
	}

	err = sshbuf_put_ebox_stream(buf, kbackup);
	if (err != ERRF_OK)
		goto out;
	err = sshbuf_put_ebox_stream_chunk(buf, chunk);
	if (err != ERRF_OK)
		goto out;

	strlcpy(fname, ca->ca_base_path, sizeof (fname));
	strlcat(fname, "/", sizeof (fname));
	strlcat(fname, ca->ca_slug, sizeof (fname));
	strlcat(fname, ".key.ebox", sizeof (fname));

	baf = fopen(fname, "w");
	if (baf == NULL) {
		err = errf("MetadataError", errfno("fopen", errno, NULL),
		    "Failed to open CA key backup file '%s' for writing",
		    fname);
		goto out;
	}

	done = fwrite(sshbuf_ptr(buf), 1, sshbuf_len(buf), baf);
	if (done < 0) {
		err = errf("MetadataError", errfno("fwrite", errno, NULL),
		    "Failed to write to CA key backup file '%s'",
		    fname);
		goto out;
	}
	if (done != sshbuf_len(buf)) {
		err = errf("MetadataError", errf("ShortWrite", NULL,
		    "Short write: %zu instead of %zu", done, sshbuf_len(buf)),
		    "Failed to write to CA key backup file '%s'",
		    fname);
		goto out;
	}

out:
	sshbuf_free(buf);
	sshbuf_free(kbuf);
	ebox_stream_chunk_free(chunk);
	ebox_stream_free(kbackup);
	if (baf != NULL)
		fclose(baf);
	return (err);
}

static errf_t *
ca_write_pukpin(struct ca *ca, enum piv_pin type, const char *pin)
{
	struct sshbuf *buf = NULL;
	struct ebox *box = NULL;
	size_t done;
	int rc;
	FILE *baf = NULL;
	char fname[PATH_MAX];
	errf_t *err;
	struct ca_ebox_tpl *cet;
	const char *typeslug;

	buf = sshbuf_new();
	if (buf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	switch (type) {
	case PIV_PIN:
	case PIV_GLOBAL_PIN:
		cet = ca->ca_pin_tpl;
		typeslug = "pin";
		break;
	case PIV_PUK:
		cet = ca->ca_puk_tpl;
		typeslug = "puk";
		break;
	default:
		VERIFY(0);
	}

	err = ebox_create(cet->cet_tpl, pin, strlen(pin), NULL, 0, &box);
	if (err != ERRF_OK) {
		goto out;
	}

	err = sshbuf_put_ebox(buf, box);
	if (err != ERRF_OK)
		goto out;

	strlcpy(fname, ca->ca_base_path, sizeof (fname));
	strlcat(fname, "/", sizeof (fname));
	strlcat(fname, ca->ca_slug, sizeof (fname));
	strlcat(fname, ".", sizeof (fname));
	strlcat(fname, typeslug, sizeof (fname));
	strlcat(fname, ".ebox", sizeof (fname));

	baf = fopen(fname, "w");
	if (baf == NULL) {
		err = errf("MetadataError", errfno("fopen", errno, NULL),
		    "Failed to open CA %s file '%s' for writing",
		    typeslug, fname);
		goto out;
	}

	done = fwrite(sshbuf_ptr(buf), 1, sshbuf_len(buf), baf);
	if (done < 0) {
		err = errf("MetadataError", errfno("fwrite", errno, NULL),
		    "Failed to write to CA %s file '%s'",
		    typeslug, fname);
		goto out;
	}
	if (done != sshbuf_len(buf)) {
		err = errf("MetadataError", errf("ShortWrite", NULL,
		    "Short write: %zu instead of %zu", done, sshbuf_len(buf)),
		    "Failed to write to CA %s file '%s'",
		    typeslug, fname);
		goto out;
	}

out:
	sshbuf_free(buf);
	ebox_free(box);
	if (baf != NULL)
		fclose(baf);
	return (err);
}

static errf_t *
ca_gen_ebox_tpls(struct ca *ca, json_object **robjp)
{
	json_object *robj = NULL, *obj;
	struct ca_ebox_tpl *cet;
	errf_t *err;
	struct sshbuf *buf;

	robj = json_object_new_object();
	VERIFY(robj != NULL);

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	for (cet = ca->ca_ebox_tpls; cet != NULL; cet = cet->cet_next) {
		char *tmp;

		if (cet->cet_refcnt == 0 || cet->cet_tpl == NULL)
			continue;

		sshbuf_reset(buf);

		err = sshbuf_put_ebox_tpl(buf, cet->cet_tpl);
		if (err != ERRF_OK)
			goto out;

		tmp = sshbuf_dtob64_string(buf, 0);
		VERIFY(tmp != NULL);
		obj = json_object_new_string(tmp);
		VERIFY(obj != NULL);
		json_object_object_add(robj, cet->cet_name, obj);
		free(tmp);
	}

	*robjp = robj;
	robj = NULL;
	err = ERRF_OK;

out:
	json_object_put(robj);
	sshbuf_free(buf);
	return (err);
}

static errf_t *
ca_gen_ebox_assigns(struct ca *ca, json_object **robjp)
{
	json_object *robj = NULL, *obj;
	struct ca_ebox_tpl *cet;
	errf_t *err;

	robj = json_object_new_object();
	VERIFY(robj != NULL);

	if (ca->ca_pin_tpl != NULL) {
		obj = json_object_new_string(ca->ca_pin_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "pin", obj);
	}

	if (ca->ca_backup_tpl != NULL) {
		obj = json_object_new_string(ca->ca_backup_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "backup", obj);
	}

	if (ca->ca_puk_tpl != NULL) {
		obj = json_object_new_string(ca->ca_puk_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "puk", obj);
	}

	if (ca->ca_admin_tpl != NULL) {
		obj = json_object_new_string(ca->ca_admin_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "admin", obj);
	}

	*robjp = robj;
	robj = NULL;
	err = ERRF_OK;

out:
	json_object_put(robj);
	return (err);
}

errf_t *
ca_generate(const char *path, struct ca_new_args *args, struct piv_token *tkn,
    struct ca **out)
{
	struct ca *ca;
	errf_t *err;
	char fname[PATH_MAX];
	FILE *caf = NULL, *crtf = NULL;
	struct sshkey *cakey = NULL, *pubkey = NULL;
	int sshkt;
	uint sshksz;
	int rc;
	size_t done;
	char *newpin = NULL, *newpuk = NULL;
	struct piv_chuid *chuid = NULL;
	struct piv_fascn *fascn = NULL;
	struct piv_pinfo *pinfo = NULL;
	struct ebox_stream *kbackup = NULL;
	struct ebox_stream_chunk *chunk;
	struct sshbuf *buf = NULL;
	struct piv_slot *caslot, *slot;
	X509 *cert = NULL;
	struct cert_var *cv;
	BIGNUM *serial = NULL;
	ASN1_INTEGER *serial_asn1 = NULL;
	const struct cert_tpl *tpl;
	size_t cdlen;
	uint8_t *cdata = NULL;
	uint flags;
	uint8_t *nadmin_key = NULL;
	size_t nadmin_len = 0;
	uint8_t *hcroot = NULL;
	size_t hcroot_len = 0;
	struct sshkey *cak;
	struct cert_var_scope *scope;
	json_object *robj = NULL, *obj = NULL;
	char *dnstr = NULL, *guidhex = NULL;
	const char *jsonstr;

	ca = calloc(1, sizeof(struct ca));
	if (ca == NULL)
		return (errfno("calloc", errno, NULL));

	ca->ca_base_path = strdup(path);
	if (ca->ca_base_path == NULL) {
		err = errfno("strdup", errno, NULL);
		goto out;
	}

	rc = mkdir(path, 0700);
	if (rc != 0 && errno != EEXIST) {
		err = errfno("mkdir(%s)", rc, path);
		goto out;
	}

	strlcpy(fname, path, sizeof (fname));
	strlcat(fname, "/pivy-ca.json", sizeof (fname));

	caf = fopen(fname, "w");
	if (caf == NULL) {
		err = errf("MetadataError", errfno("fopen", errno, NULL),
		    "Failed to open CA metadata file '%s' for writing",
		    fname);
		goto out;
	}

	ca->ca_dn = args->cna_dn;
	args->cna_dn = NULL;

	ca_recalc_slug(ca);

	ca->ca_ebox_tpls = args->cna_ebox_tpls;
	args->cna_ebox_tpls = NULL;

	ca->ca_backup_tpl = args->cna_backup_tpl;
	ca->ca_pin_tpl = args->cna_pin_tpl;
	ca->ca_puk_tpl = args->cna_puk_tpl;

	arc4random_buf(ca->ca_guid, sizeof (ca->ca_guid));

	nadmin_key = malloc_conceal(args->cna_init_admin_len);
	if (nadmin_key == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	nadmin_len = args->cna_init_admin_len;

	arc4random_buf(nadmin_key, nadmin_len);

	hcroot = malloc_conceal(64);
	if (hcroot == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	hcroot_len = 64;

	arc4random_buf(hcroot, hcroot_len);

	newpin = generate_pin();
	newpuk = generate_pin();

	fascn = piv_fascn_zero();
	chuid = piv_chuid_new();
	piv_chuid_set_fascn(chuid, fascn);
	piv_chuid_set_guid(chuid, ca->ca_guid);
	piv_chuid_set_expiry_rel(chuid, 3600*24*365*20);

	pinfo = piv_pinfo_new();
	piv_pinfo_set_expiry_rel(pinfo, 3600*24*365*20);
	piv_pinfo_set_name(pinfo, ca->ca_slug);
	piv_pinfo_set_affiliation(pinfo, "Certification Authority");

	ykpiv_pinfo_set_admin_key(pinfo, nadmin_key, nadmin_len);

	piv_pinfo_set_kv(pinfo, "ca_hc", hcroot, hcroot_len);

	if ((err = piv_txn_begin(tkn)) ||
	    (err = piv_select(tkn)))
		goto out;

	err = piv_auth_admin(tkn, args->cna_init_admin,
	    args->cna_init_admin_len, args->cna_init_admin_alg);
	if (err != ERRF_OK) {
		err = errf("InitialStateError", err, "Initial admin key given "
		    "to ca_generate does not match token");
		goto out;
	}

	err = piv_write_chuid(tkn, chuid);
	if (err != ERRF_OK)
		goto out;

	err = piv_write_pinfo(tkn, pinfo);
	if (err != ERRF_OK)
		goto out;

	err = ca_write_pukpin(ca, PIV_PIN, newpin);
	if (err != ERRF_OK)
		goto out;
	err = ca_write_pukpin(ca, PIV_PUK, newpuk);
	if (err != ERRF_OK)
		goto out;

	err = piv_change_pin(tkn, PIV_PUK, args->cna_init_puk, newpuk);
	if (err != ERRF_OK)
		goto out;
	err = piv_change_pin(tkn, PIV_PIN, args->cna_init_pin, newpin);
	if (err != ERRF_OK)
		goto out;

	switch (args->cna_key_alg) {
	case PIV_ALG_RSA1024:
		sshkt = KEY_RSA;
		sshksz = 1024;
		break;
	case PIV_ALG_RSA2048:
		sshkt = KEY_RSA;
		sshksz = 2048;
		break;
	case PIV_ALG_ECCP256:
		sshkt = KEY_ECDSA;
		sshksz = 256;
		break;
	case PIV_ALG_ECCP384:
		sshkt = KEY_ECDSA;
		sshksz = 384;
		break;
	default:
		err = errf("UnsupportedAlgorithm", NULL, "PIV algorithm "
		    "%d (%s) not supported for CA key", args->cna_key_alg,
		    piv_alg_to_string(args->cna_key_alg));
	}

	rc = sshkey_generate(sshkt, sshksz, &cakey);
	if (rc != 0) {
		err = ssherrf("sshkey_generate", rc);
		goto out;
	}

	rc = sshkey_demote(cakey, &pubkey);
	if (rc != 0) {
		err = ssherrf("sshkey_demote", rc);
		goto out;
	}

	err = ca_write_key_backup(ca, cakey);
	if (err != ERRF_OK)
		goto out;

	err = ykpiv_import(tkn, PIV_SLOT_SIGNATURE, cakey, YKPIV_PIN_ALWAYS,
	    YKPIV_TOUCH_NEVER);
	if (err)
		goto out;

	caslot = piv_force_slot(tkn, PIV_SLOT_SIGNATURE, args->cna_key_alg);

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	VERIFY(serial != NULL);
	VERIFY(BN_pseudo_rand(serial, 160, 0, 0) == 1);
	VERIFY(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);

	cert = X509_new();
	VERIFY(cert != NULL);
	VERIFY(X509_set_version(cert, 2) == 1);
	VERIFY(X509_set_serialNumber(cert, serial_asn1) == 1);

	tpl = cert_tpl_find("ca");

	cv = scope_lookup(args->cna_scope, "lifetime", 1);
	if (!cert_var_defined(cv)) {
		err = cert_var_set(cv, "20y");
		if (err)
			goto out;
	}
	err = scope_set(args->cna_scope, "dn", "cn=dummy");
	if (err != ERRF_OK)
		goto out;

	err = cert_tpl_populate(tpl, args->cna_scope, cert);
	if (err != ERRF_OK) {
		err = errf("CertificateError", err, "Error populating "
		    "CA certificate attributes");
		goto out;
	}

	VERIFY(X509_set_subject_name(cert, ca->ca_dn) == 1);
	VERIFY(X509_set_issuer_name(cert, ca->ca_dn) == 1);

	err = piv_verify_pin(tkn, PIV_PIN, newpin, NULL, B_FALSE);
	if (err != ERRF_OK)
		goto out;

	err = piv_selfsign_cert(tkn, caslot, pubkey, cert);
	if (err != ERRF_OK) {
		err = errf("CertificateError", err, "Error self-signing "
		    "CA certificate");
		goto out;
	}

	rc = X509_verify(cert, X509_get_pubkey(cert));
	if (rc != 1) {
		make_sslerrf(err, "X509_verify", "verifying cert");
		err = errf("CertificateError", err, "Error verifying "
		    "self-signed CA certificate");
		goto out;
	}

	rc = i2d_X509(cert, &cdata);
	if (cdata == NULL || rc <= 0) {
		make_sslerrf(err, "i2d_X509", "serialising cert");
		goto out;
	}
	cdlen = (size_t)rc;

	flags = PIV_COMP_NONE;
	err = piv_write_cert(tkn, PIV_SLOT_SIGNATURE, cdata, cdlen, flags);
	if (err != ERRF_OK)
		goto out;

	strlcpy(fname, path, sizeof (fname));
	strlcat(fname, "/", sizeof (fname));
	strlcat(fname, ca->ca_slug, sizeof (fname));
	strlcat(fname, ".crt", sizeof (fname));

	crtf = fopen(fname, "w");
	if (crtf == NULL) {
		err = errf("MetadataError", errfno("fopen", errno, NULL),
		    "Failed to open CA cert file '%s' for writing",
		    fname);
		goto out;
	}

	rc = PEM_write_X509(crtf, cert);
	if (rc != 1) {
		make_sslerrf(err, "PEM_write_X509", "writing out CA cert");
		goto out;
	}

	fclose(crtf);
	crtf = NULL;

	ca->ca_cert = cert;
	cert = NULL;

	OPENSSL_free(cdata);
	cdata = NULL;

	err = piv_generate(tkn, PIV_SLOT_CARD_AUTH, PIV_ALG_ECCP256, &cak);
	if (err != ERRF_OK)
		goto out;

	slot = piv_force_slot(tkn, PIV_SLOT_CARD_AUTH, PIV_ALG_ECCP256);

	VERIFY(BN_pseudo_rand(serial, 160, 0, 0) == 1);
	VERIFY(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);

	cert = X509_new();
	VERIFY(cert != NULL);
	VERIFY(X509_set_version(cert, 2) == 1);
	VERIFY(X509_set_serialNumber(cert, serial_asn1) == 1);

	tpl = cert_tpl_find("user-auth");
	scope = scope_new_root();
	VERIFY(scope != NULL);
	if ((err = scope_set(scope, "slug", ca->ca_slug)) ||
	    (err = scope_set(scope, "dn", "cn=ca-card-auth, ou=%{slug}")) ||
	    (err = scope_set(scope, "lifetime", "20y")))
		goto out;

	err = cert_tpl_populate(tpl, scope, cert);
	if (err != ERRF_OK) {
		err = errf("CertificateError", err, "Error populating "
		    "CA certificate attributes");
		goto out;
	}

	err = piv_selfsign_cert(tkn, slot, cak, cert);
	if (err != ERRF_OK)
		goto out;

	err = piv_verify_pin(tkn, PIV_PIN, newpin, NULL, B_FALSE);
	if (err != ERRF_OK)
		goto out;

	err = piv_sign_cert(tkn, caslot, pubkey, cert);
	if (err != ERRF_OK) {
		err = errf("CertificateError", err, "Error signing "
		    "CAK certificate");
		goto out;
	}

	rc = i2d_X509(cert, &cdata);
	if (cdata == NULL || rc <= 0) {
		make_sslerrf(err, "i2d_X509", "serialising cert");
		goto out;
	}
	cdlen = (size_t)rc;

	flags = PIV_COMP_NONE;
	err = piv_write_cert(tkn, PIV_SLOT_CARD_AUTH, cdata, cdlen, flags);
	if (err != ERRF_OK)
		goto out;

	ca->ca_cak = cak;
	cak = NULL;

	robj = json_object_new_object();
	VERIFY(robj != NULL);

	err = unparse_dn(ca->ca_dn, &dnstr);
	if (err != ERRF_OK)
		goto out;
	obj = json_object_new_string(dnstr);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "dn", obj);

	buf = sshbuf_from(ca->ca_guid, sizeof (ca->ca_guid));
	guidhex = sshbuf_dtob16(buf);
	obj = json_object_new_string(guidhex);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "guid", obj);

	sshbuf_free(buf);
	buf = sshbuf_new();
	VERIFY(buf != NULL);
	rc = sshkey_format_text(ca->ca_cak, buf);
	if (rc != 0) {
		err = ssherrf("sshkey_format_text", rc);
		goto out;
	}
	VERIFY0(sshbuf_put_u8(buf, '\0'));
	obj = json_object_new_string((char *)sshbuf_ptr(buf));
	VERIFY(obj != NULL);
	json_object_object_add(robj, "cak", obj);

	obj = json_object_new_array();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "crl", obj);

	obj = json_object_new_array();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "ocsp", obj);

	err = ca_gen_ebox_tpls(ca, &obj);
	if (err != ERRF_OK)
		goto out;
	json_object_object_add(robj, "ebox_templates", obj);

	err = ca_gen_ebox_assigns(ca, &obj);
	if (err != ERRF_OK)
		goto out;
	json_object_object_add(robj, "eboxes", obj);

	obj = json_object_new_object();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "cert_templates", obj);

	obj = json_object_new_object();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "token_templates", obj);

	obj = json_object_new_object();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "variables", obj);

	err = piv_verify_pin(tkn, PIV_PIN, newpin, NULL, B_FALSE);
	if (err != ERRF_OK)
		goto out;

	err = piv_sign_json(tkn, caslot, NULL, robj);
	if (err != ERRF_OK)
		goto out;

	jsonstr = json_object_to_json_string_ext(robj, JSON_C_TO_STRING_PRETTY);
	done = fwrite(jsonstr, 1, strlen(jsonstr), caf);
	if (done < 0) {
		err = errfno("fwrite", errno, "writing CA json");
		goto out;
	} else if (done < strlen(jsonstr)) {
		err = errf("ShortWrite", NULL, "wrote %zu bytes instead of "
		    "%zu", done, strlen(jsonstr));
		goto out;
	}
	fclose(caf);
	caf = NULL;

	*out = ca;
	ca = NULL;
	err = ERRF_OK;

out:
	if (piv_token_in_txn(tkn))
		piv_txn_end(tkn);
	sshbuf_free(buf);
	scope_free_root(scope);
	sshkey_free(cakey);
	sshkey_free(pubkey);
	sshkey_free(cak);
	X509_free(cert);
	OPENSSL_free(cdata);
	piv_chuid_free(chuid);
	piv_fascn_free(fascn);
	piv_pinfo_free(pinfo);
	json_object_put(robj);
	free(dnstr);
	free(guidhex);
	BN_free(serial);
	ASN1_INTEGER_free(serial_asn1);
	if (newpin != NULL)
		freezero(newpin, strlen(newpin));
	if (newpuk != NULL)
		freezero(newpuk, strlen(newpuk));
	freezero(nadmin_key, nadmin_len);
	freezero(hcroot, hcroot_len);
	ca_close(ca);
	if (caf != NULL)
		fclose(caf);
	if (crtf != NULL)
		fclose(crtf);
	cana_free(args);
	return (err);
}

errf_t *
ca_open(const char *path, struct ca **outca)
{
	struct ca *ca;
	errf_t *err;
	char *buf = NULL;
	size_t len;
	char fname[PATH_MAX];
	int rc;
	json_object *robj = NULL, *obj = NULL;
	enum json_tokener_error jerr;
	struct json_tokener *tok = NULL;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	struct sshbuf *sbuf = NULL;
	char *p;
	json_object_iter iter;

	ca = calloc(1, sizeof(struct ca));
	if (ca == NULL)
		return (errfno("calloc", errno, NULL));

	sbuf = sshbuf_new();
	if (sbuf == NULL) {
		err = errfno("sshbuf_new", errno, NULL);
		goto out;
	}

	ca->ca_base_path = strdup(path);
	if (ca->ca_base_path == NULL) {
		err = errfno("strdup", errno, NULL);
		goto out;
	}

	strlcpy(fname, path, sizeof (fname));
	strlcat(fname, "/pivy-ca.json", sizeof (fname));

	err = read_text_file(fname, &buf, &len);
	if (err != ERRF_OK)
		goto metaerr;

	tok = json_tokener_new();
	if (tok == NULL) {
		err = errfno("json_tokener_new", errno, NULL);
		goto out;
	}

	robj = json_tokener_parse_ex(tok, buf, len + 1);
	if ((jerr = json_tokener_get_error(tok)) != json_tokener_success) {
		err = jtokerrf("json_tokener_parse_ex", jerr);
		goto metaerr;
	}
	VERIFY(robj != NULL);
	if (json_tokener_get_parse_end(tok) < len) {
		err = errf("LengthError", NULL, "JSON object ended after "
		    "%zu bytes, expected %zu", json_tokener_get_parse_end(tok),
		    len);
		goto metaerr;
	}

	obj = json_object_object_get(robj, "dn");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'dn' property");
		goto metaerr;
	}
	ca->ca_dn = X509_NAME_new();
	if (ca->ca_dn == NULL) {
		make_sslerrf(err, "X509_NAME_new", "allocating CA DN");
		goto out;
	}
	err = parse_dn(json_object_get_string(obj), ca->ca_dn);
	if (err != ERRF_OK) {
		err = errf("InvalidProperty", NULL, "CA JSON has invalid 'dn' "
		    "property: '%s'", json_object_get_string(obj));
		goto metaerr;
	}

	ca_recalc_slug(ca);

	strlcpy(fname, path, sizeof (fname));
	strlcat(fname, "/", sizeof (fname));
	strlcat(fname, ca->ca_slug, sizeof (fname));
	strlcat(fname, ".crt", sizeof (fname));

	err = read_text_file(fname, &buf, &len);
	if (err != ERRF_OK)
		goto metaerr;

	bio = BIO_new_mem_buf(buf, len);
	if (bio == NULL) {
		make_sslerrf(err, "BIO_new", "allocating memory BIO");
		goto out;
	}

	ca->ca_cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (ca->ca_cert == NULL) {
		make_sslerrf(err, "PEM_read_bio_X509", "parsing CA cert");
		goto metaerr;
	}

	BIO_free(bio);
	bio = NULL;

	pkey = X509_get_pubkey(ca->ca_cert);
	rc = sshkey_from_evp_pkey(pkey, KEY_UNSPEC, &ca->ca_pubkey);
	if (rc != 0) {
		err = ssherrf("sshkey_from_evp_pkey", rc);
		goto metaerr;
	}

	err = verify_json(ca->ca_pubkey, NULL, robj);
	if (err != ERRF_OK) {
		err = errf("CADataError", err, "Failed to validate CA "
		    "configuration signature");
		goto out;
	}

	obj = json_object_object_get(robj, "guid");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'guid' property");
		goto out;
	}
	sshbuf_reset(sbuf);
	err = sshbuf_b16tod(json_object_get_string(obj), sbuf);
	if (err != ERRF_OK) {
		err = errf("InvalidProperty", NULL, "CA JSON has invalid "
		    "'guid' property: '%s'", json_object_get_string(obj));
		goto out;
	}
	if (sshbuf_len(sbuf) != sizeof (ca->ca_guid)) {
		err = errf("InvalidProperty", NULL, "CA JSON has invalid "
		    "'guid' property: %zu bytes, expected %zu",
		    sshbuf_len(sbuf), sizeof (ca->ca_guid));
		goto out;
	}
	rc = sshbuf_get(sbuf, ca->ca_guid, sizeof (ca->ca_guid));
	if (rc != 0) {
		err = ssherrf("sshbuf_get", rc);
		goto out;
	}

	obj = json_object_object_get(robj, "cak");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'cak' property");
		goto out;
	}
	ca->ca_cak = sshkey_new(KEY_UNSPEC);
	VERIFY(ca->ca_cak != NULL);
	p = (char *)json_object_get_string(obj);
	rc = sshkey_read(ca->ca_cak, &p);
	if (rc != 0) {
		err = ssherrf("sshkey_read", rc);
		err = errf("InvalidProperty", err, "CA JSON has invalid "
		    "'cak' property: '%s'", json_object_get_string(obj));
		goto out;
	}

	obj = json_object_object_get(robj, "crl");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'crl' property");
		goto out;
	}
	err = read_uri_array(obj, &ca->ca_crls);
	if (err != ERRF_OK) {
		err = errf("InvalidProperty", err, "CA JSON has invalid "
		    "'crl' property: '%s'", json_object_get_string(obj));
		goto out;
	}

	obj = json_object_object_get(robj, "ocsp");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'ocsp' property");
		goto out;
	}
	err = read_uri_array(obj, &ca->ca_ocsps);
	if (err != ERRF_OK) {
		err = errf("InvalidProperty", err, "CA JSON has invalid "
		    "'ocsp' property: '%s'", json_object_get_string(obj));
		goto out;
	}

	obj = json_object_object_get(robj, "ebox_templates");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'ebox_templates' property");
		goto out;
	}
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		err = parse_ebox_template(ca, iter.key, iter.val);
		if (err != ERRF_OK) {
			err = errf("InvalidProperty", err, "CA JSON has "
			    "invalid 'ebox_templates' property");
			goto out;
		}
	}

	obj = json_object_object_get(robj, "eboxes");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'eboxes' property");
		goto out;
	}
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		err = parse_ebox_spec(ca, iter.key, iter.val);
		if (err != ERRF_OK) {
			err = errf("InvalidProperty", err, "CA JSON has "
			    "invalid 'eboxes' property");
			goto out;
		}
	}

	obj = json_object_object_get(robj, "cert_templates");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'cert_templates' property");
		goto out;
	}
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		err = parse_cert_template(ca, iter.key, iter.val);
		if (err != ERRF_OK) {
			err = errf("InvalidProperty", err, "CA JSON has "
			    "invalid 'cert_templates' property");
			goto out;
		}
	}

	obj = json_object_object_get(robj, "token_templates");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'token_templates' property");
		goto out;
	}
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		err = parse_token_template(ca, iter.key, iter.val);
		if (err != ERRF_OK) {
			err = errf("InvalidProperty", err, "CA JSON has "
			    "invalid 'token_templates' property");
			goto out;
		}
	}

	ca->ca_vars = json_object_object_get(robj, "variables");
	if (ca->ca_vars != NULL)
		json_object_put(ca->ca_vars);

	*outca = ca;
	ca = NULL;
out:
	ca_close(ca);
	free(buf);
	sshbuf_free(sbuf);
	json_object_put(robj);
	EVP_PKEY_free(pkey);
	if (tok != NULL)
		json_tokener_free(tok);
	BIO_free(bio);
	return (err);

metaerr:
	err = errf("CAMetadataError", err, "Failed to read CA "
	    "metadata file '%s'", fname);
	goto out;
}

static errf_t *
set_scope_from_json(struct cert_var_scope *scope, json_object *obj)
{
	json_object_iter iter;
	errf_t *err;
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		err = scope_set(scope, iter.key,
		    json_object_get_string(iter.val));
		if (err != ERRF_OK)
			return (err);
	}
	return (ERRF_OK);
}

struct cert_var_scope *
ca_make_scope(struct ca *ca, struct cert_var_scope *parent)
{
	struct cert_var_scope *sc;
	errf_t *err;

	sc = scope_new_empty(parent);
	if (sc == NULL)
		return (NULL);

	if (ca->ca_vars != NULL) {
		err = set_scope_from_json(sc, ca->ca_vars);
		if (err != ERRF_OK) {
			errf_free(err);
			return (NULL);
		}
	}

	return (sc);
}

struct ca_cert_tpl *
ca_cert_tpl_first(struct ca *ca)
{
	return (ca->ca_cert_tpls);
}

struct ca_cert_tpl *
ca_cert_tpl_next(struct ca_cert_tpl *tpl)
{
	return (tpl->cct_next);
}

struct ca_cert_tpl *
ca_cert_tpl_get(struct ca *ca, const char *name)
{
	struct ca_cert_tpl *tpl;
	for (tpl = ca->ca_cert_tpls; tpl != NULL; tpl = tpl->cct_next) {
		if (strcmp(tpl->cct_name, name) == 0) {
			return (tpl);
		}
	}
	return (NULL);
}

errf_t *
ca_cert_tpl_add(struct ca *ca, struct ca_cert_tpl *tpl)
{
	VERIFY(tpl->cct_ca == NULL);
	VERIFY(tpl->cct_prev == NULL);
	VERIFY(tpl->cct_next == NULL);

	if (ca_cert_tpl_get(ca, tpl->cct_name) != NULL) {
		return (errf("DuplicateCertTemplate", NULL, "A cert template "
		    "with name '%s' already exists in this CA", tpl->cct_name));
	}

	tpl->cct_next = ca->ca_cert_tpls;
	if (ca->ca_cert_tpls != NULL)
		ca->ca_cert_tpls->cct_prev = tpl;
	ca->ca_cert_tpls = tpl;

	return (ERRF_OK);
}

errf_t *
ca_cert_tpl_remove(struct ca *ca, struct ca_cert_tpl *tpl)
{
	VERIFY(ca == tpl->cct_ca);
	VERIFY(ca->ca_cert_tpls == tpl || tpl->cct_next != NULL ||
	    tpl->cct_prev != NULL);

	if (tpl->cct_prev != NULL)
		tpl->cct_prev->cct_next = tpl->cct_next;
	if (tpl->cct_next != NULL)
		tpl->cct_next->cct_prev = tpl->cct_prev;
	if (ca->ca_cert_tpls == tpl)
		ca->ca_cert_tpls = tpl->cct_next;
	tpl->cct_next = NULL;
	tpl->cct_prev = NULL;
	tpl->cct_ca = NULL;

	return (ERRF_OK);
}

struct ca_cert_tpl *
ca_cert_tpl_new(const char *name, const char *help,
    enum ca_cert_type type, enum ca_cert_tpl_flags flags,
    const struct cert_tpl *tpl, struct cert_var_scope *tplscope)
{
	return (NULL);
}

const char *
ca_cert_tpl_name(const struct ca_cert_tpl *tpl)
{
	return (tpl->cct_name);
}

const char *
ca_cert_tpl_help(const struct ca_cert_tpl *tpl)
{
	return (tpl->cct_help);
}

enum ca_cert_type
ca_cert_tpl_type(const struct ca_cert_tpl *tpl)
{
	return (tpl->cct_type);
}

enum ca_cert_tpl_flags
ca_cert_tpl_flags(const struct ca_cert_tpl *tpl)
{
	return (tpl->cct_flags);
}

const struct cert_tpl *
ca_cert_tpl_tpl(const struct ca_cert_tpl *tpl)
{
	return (tpl->cct_tpl);
}

struct cert_var_scope *
ca_cert_tpl_make_scope(struct ca_cert_tpl *tpl, struct cert_var_scope *parent)
{
	struct cert_var_scope *sc;
	errf_t *err;

	sc = scope_new_for_tpl(parent, tpl->cct_tpl);
	if (sc == NULL)
		return (NULL);

	if (tpl->cct_vars != NULL) {
		err = set_scope_from_json(sc, tpl->cct_vars);
		if (err != ERRF_OK) {
			errf_free(err);
			return (NULL);
		}
	}

	return (sc);
}

errf_t *
ca_open_session(struct ca *ca, struct ca_session **outsess)
{
	struct ca_session *sess = NULL;
	struct ca_session_agent *sa;
	struct ca_session_direct *sd;
	errf_t *err;
	int rc;
	long rv;
	uint i;
	int found = 0, in_txn = 0;
	struct sshkey *k;

	sess = calloc(1, sizeof (struct ca_session));
	if (sess == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	sess->cs_ca = ca;

	sess->cs_type = CA_SESSION_AGENT;
	sa = &sess->cs_agent;

	rc = ssh_get_authentication_socket(&sa->csa_fd);
	if (rc != 0) {
		goto direct;
	}

	rc = ssh_fetch_identitylist(sa->csa_fd, &sa->csa_idl);
	if (rc != 0) {
		close(sa->csa_fd);
		goto direct;
	}

	for (i = 0; i < sa->csa_idl->nkeys; ++i) {
		k = sa->csa_idl->keys[i];
		if (sshkey_equal_public(k, ca->ca_pubkey)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		ssh_free_identitylist(sa->csa_idl);
		close(sa->csa_fd);
		goto direct;
	}

	rc = sshkey_generate(KEY_ECDSA, 256, &sa->csa_rebox_key);
	if (rc != 0) {
		err = ssherrf("sshkey_generate", rc);
		goto out;
	}

	goto good;

direct:
	sess->cs_type = CA_SESSION_DIRECT;
	sd = &sess->cs_direct;
	bzero(sd, sizeof (*sd));

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &sd->csd_context);
	if (rv != SCARD_S_SUCCESS) {
		err = pcscerrf("SCardEstablishContext", rv);
		goto out;
	}

	err = piv_find(sd->csd_context, ca->ca_guid, sizeof (ca->ca_guid),
	    &sd->csd_token);
	if (err != ERRF_OK)
		goto out;

	err = piv_txn_begin(sd->csd_token);
	if (err != ERRF_OK)
		goto out;
	in_txn = 1;

	err = piv_select(sd->csd_token);
	if (err != ERRF_OK)
		goto out;

	err = piv_read_cert(sd->csd_token, PIV_SLOT_CARD_AUTH);
	if (err != ERRF_OK)
		goto out;

	sd->csd_cakslot = piv_get_slot(sd->csd_token, PIV_SLOT_CARD_AUTH);

	err = piv_auth_key(sd->csd_token, sd->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK)
		goto out;

	err = piv_read_cert(sd->csd_token, PIV_SLOT_SIGNATURE);
	if (err != ERRF_OK)
		goto out;

	sd->csd_slot = piv_get_slot(sd->csd_token, PIV_SLOT_SIGNATURE);

	k = piv_slot_pubkey(sd->csd_slot);
	if (!sshkey_equal_public(ca->ca_pubkey, k)) {
		err = errf("KeyAuthError", NULL, "CA public key does not "
		    "match key in slot 9C");
		goto out;
	}

	piv_txn_end(sd->csd_token);
	in_txn = 0;

good:
	sess->cs_next = ca->ca_sessions;
	if (ca->ca_sessions != NULL)
		ca->ca_sessions->cs_prev = sess;
	ca->ca_sessions = sess->cs_next;
	*outsess = sess;
	sess = NULL;

out:
	if (in_txn)
		piv_txn_end(sess->cs_direct.csd_token);
	ca_close_session(sess);
	return (err);
}

void
ca_close_session(struct ca_session *sess)
{
	if (sess->cs_ca->ca_sessions == sess)
		sess->cs_ca->ca_sessions = sess->cs_next;
	if (sess->cs_next != NULL)
		sess->cs_next->cs_prev = sess->cs_prev;
	if (sess->cs_prev != NULL)
		sess->cs_prev->cs_next = sess->cs_next;

	if (sess->cs_type == CA_SESSION_AGENT) {
		struct ca_session_agent *csa = &sess->cs_agent;
		ssh_free_identitylist(csa->csa_idl);
		close(csa->csa_fd);
		sshkey_free(csa->csa_rebox_key);

	} else if (sess->cs_type == CA_SESSION_DIRECT) {
		struct ca_session_direct *csd = &sess->cs_direct;
		piv_release(csd->csd_token);
		SCardReleaseContext(csd->csd_context);

	} else {
		VERIFY(0);
	}

	free(sess);
}
