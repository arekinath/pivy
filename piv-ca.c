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

#include <json.h>

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/authfd.h"

#include <openssl/asn1.h>
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
#include "pkinit_asn1.h"
#include "piv-ca.h"

/* We need the piv_cert_comp enum */
#include "piv-internal.h"

#if !defined(JSONC_14)
size_t json_tokener_get_parse_end(struct json_tokener *);

size_t
json_tokener_get_parse_end(struct json_tokener *tok)
{
	return ((size_t)tok->char_offset);
}
#endif

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
	char			*ca_guidhex;
	enum piv_slotid		 ca_slot;
	struct sshkey		*ca_cak;
	X509_NAME		*ca_dn;
	boolean_t		 ca_crls_want_idp;

	unsigned long		 ca_crl_lifetime;

	boolean_t		 ca_dirty;

	json_object		*ca_vars;
	json_object		*ca_req_vars;

	X509			*ca_cert;
	struct sshkey		*ca_pubkey;

	struct ca_uri		*ca_crls;
	struct ca_uri		*ca_ocsps;
	struct ca_uri		*ca_aias;

	struct ca_ebox_tpl	*ca_ebox_tpls;

	struct ca_ebox_tpl	*ca_pin_tpl;
	struct ca_ebox_tpl	*ca_backup_tpl;
	struct ca_ebox_tpl	*ca_puk_tpl;
	struct ca_ebox_tpl	*ca_admin_tpl;

	struct ebox		*ca_pin_ebox;
	struct ebox		*ca_old_pin_ebox;
	struct ebox		*ca_backup_ebox;
	struct ebox		*ca_puk_ebox;
	struct ebox		*ca_admin_ebox;

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
	struct piv_ctx		*csd_context;
	struct piv_token	*csd_token;
	struct piv_slot		*csd_cakslot;
	struct piv_slot		*csd_slot;
	char			*csd_pin;
	enum piv_pin		 csd_pintype;
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
	json_object			*ctt_req_vars;
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
	json_object			*ctst_req_vars;

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
	json_object			*cct_req_vars;
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
static errf_t *ca_sign_json(struct ca *ca, struct ca_session *sess,
    json_object *obj);
static errf_t *ca_sign_cert(struct ca *ca, struct ca_session *sess, X509 *cert);

struct json_sign_ctx;
static struct json_sign_ctx *json_sign_new(void);
static errf_t *json_sign_begin(struct json_sign_ctx *ctx, json_object *obj,
    const char *subprop);
static struct sshbuf *json_sign_get_tbs(struct json_sign_ctx *ctx);
static struct sshbuf *json_sign_get_signature(struct json_sign_ctx *ctx);
static errf_t *json_sign_set_signature(struct json_sign_ctx *ctx,
    struct sshbuf *sigbuf);
static void json_sign_abort(struct json_sign_ctx *ctx);
static errf_t *json_sign_finish(struct json_sign_ctx *ctx);

errf_t *read_text_file(const char *path, char **out, size_t *outlen);
errf_t *validate_cstring(const char *buf, size_t len, size_t maxlen);

static errf_t *ca_log_init(struct ca *ca, struct ca_session *sess,
    BIGNUM *ca_serial, const char *dnstr);
static errf_t *ca_log_new_cert(struct ca *ca, struct ca_session *sess,
    const char *tpl, struct cert_var_scope *scope, X509 *cert);

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

const char *
ca_slug(const struct ca *ca)
{
	return (ca->ca_slug);
}

const char *
ca_guidhex(const struct ca *ca)
{
	return (ca->ca_guidhex);
}

const struct sshkey *
ca_pubkey(const struct ca *ca)
{
	return (ca->ca_pubkey);
}

const struct sshkey *
ca_cak(const struct ca *ca)
{
	return (ca->ca_cak);
}

char *
ca_dn(const struct ca *ca)
{
	errf_t *err;
	char *out;

	err = unparse_dn(ca->ca_dn, &out);
	if (err != ERRF_OK) {
		errf_free(err);
		return (NULL);
	}
	return (out);
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
		free(vstr);
	}

	*robjp = robj;
	robj = NULL;
	err = ERRF_OK;

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

struct json_sign_ctx {
	json_object	*jsc_obj;
	boolean_t	 jsc_hadsig;
	boolean_t	 jsc_setsig;
	json_object	*jsc_sigprop;
	json_object	*jsc_sigsubprop;
	struct sshbuf	*jsc_tbsbuf;
	struct sshbuf	*jsc_sigbuf;
};

static struct json_sign_ctx *
json_sign_new(void)
{
	struct json_sign_ctx *ctx;

	ctx = calloc(1, sizeof (struct json_sign_ctx));
	if (ctx == NULL)
		return (NULL);

	ctx->jsc_tbsbuf = sshbuf_new();
	if (ctx->jsc_tbsbuf == NULL) {
		free(ctx);
		return (NULL);
	}

	return (ctx);
}

static errf_t *
json_sign_begin(struct json_sign_ctx *ctx, json_object *obj,
    const char *subprop)
{
	const char *tmp;
	errf_t *err;
	int rc;
	struct sshbuf *tbsbuf = ctx->jsc_tbsbuf;

	VERIFY(ctx->jsc_obj == NULL);
	VERIFY(ctx->jsc_tbsbuf != NULL);

	json_object_get(obj);
	ctx->jsc_obj = obj;

	ctx->jsc_sigprop = json_object_object_get(obj, "signature");
	if (ctx->jsc_sigprop == NULL) {
		ctx->jsc_hadsig = B_FALSE;
		ctx->jsc_sigprop = json_object_new_object();
	} else {
		ctx->jsc_hadsig = B_TRUE;
		VERIFY(json_object_is_type(ctx->jsc_sigprop, json_type_object));
		json_object_get(ctx->jsc_sigprop);
		json_object_object_del(obj, "signature");
	}
	VERIFY(ctx->jsc_sigprop != NULL);

	ctx->jsc_sigsubprop = json_object_object_get(ctx->jsc_sigprop,
	    subprop);
	if (ctx->jsc_sigsubprop == NULL) {
		ctx->jsc_sigsubprop = json_object_new_string("");
		VERIFY(ctx->jsc_sigsubprop != NULL);
		rc = json_object_object_add(ctx->jsc_sigprop, subprop,
		    ctx->jsc_sigsubprop);
		if (rc != 0) {
			err = jsonerrf("json_object_object_add");
			goto out;
		}
	} else {
		tmp = json_object_get_string(ctx->jsc_sigsubprop);
		if (tmp == NULL) {
			err = errf("JSONSignatureError", NULL, "Signature "
			    "'%s' is null", subprop);
			goto out;
		}
		ctx->jsc_sigbuf = sshbuf_new();
		if (ctx->jsc_sigbuf == NULL) {
			err = errfno("sshbuf_new", errno, NULL);
			goto out;
		}
		rc = sshbuf_b64tod(ctx->jsc_sigbuf, tmp);
		if (rc != 0) {
			err = errf("JSONSignatureError",
			    ssherrf("sshbuf_b64tod", rc),
			    "Failed to parse signature '%s' as base64",
			    subprop);
			goto out;
		}
	}
	VERIFY(json_object_is_type(ctx->jsc_sigsubprop,
	    json_type_string));

	tmp = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);

	if ((rc = sshbuf_put_cstring8(tbsbuf, "piv-ca-json-signature")) ||
	    (rc = sshbuf_put_cstring8(tbsbuf, subprop)) ||
	    (rc = sshbuf_put_cstring(tbsbuf, tmp))) {
		err = ssherrf("sshbuf_put_cstring", rc);
		goto out;
	}

	err = ERRF_OK;

out:
	return (err);
}

static struct sshbuf *
json_sign_get_tbs(struct json_sign_ctx *ctx)
{
	VERIFY(ctx->jsc_obj != NULL);
	return (ctx->jsc_tbsbuf);
}

static struct sshbuf *
json_sign_get_signature(struct json_sign_ctx *ctx)
{
	return (ctx->jsc_sigbuf);
}

static errf_t *
json_sign_set_signature(struct json_sign_ctx *ctx, struct sshbuf *sigbuf)
{
	errf_t *err;
	char *sigb64 = NULL;
	int rc;

	sigb64 = sshbuf_dtob64_string(sigbuf, 0);
	if (sigb64 == NULL) {
		err = errf("ConversionError", NULL, "Failed to convert "
		    "signature value to base64");
		goto out;
	}

	rc = json_object_set_string(ctx->jsc_sigsubprop, sigb64);
	if (rc != 1) {
		err = jsonerrf("json_object_set_string");
		goto out;
	}

	ctx->jsc_setsig = B_TRUE;
	err = ERRF_OK;

out:
	free(sigb64);
	return (err);
}

static void
json_sign_abort(struct json_sign_ctx *ctx)
{
	errf_t *err;

	if (ctx == NULL)
		return;
	ctx->jsc_setsig = B_FALSE;
	err = json_sign_finish(ctx);
	errf_free(err);
}

static errf_t *
json_sign_finish(struct json_sign_ctx *ctx)
{
	errf_t *err;
	int rc;

	if (ctx == NULL)
		return (ERRF_OK);

	if (ctx->jsc_hadsig || ctx->jsc_setsig) {
		rc = json_object_object_add(ctx->jsc_obj, "signature",
		    ctx->jsc_sigprop);
		if (rc != 0) {
			err = jsonerrf("json_object_object_add");
			goto out;
		}
		/* json_object_object_add takes ownership */
		ctx->jsc_sigprop = NULL;
		ctx->jsc_sigsubprop = NULL;
	}

	err = ERRF_OK;

out:
	json_object_put(ctx->jsc_sigprop);
	sshbuf_free(ctx->jsc_tbsbuf);
	sshbuf_free(ctx->jsc_sigbuf);
	json_object_put(ctx->jsc_obj);
	free(ctx);

	return (err);
}

static errf_t *
agent_sign_json(int fd, struct sshkey *pubkey, const char *subprop,
    json_object *obj)
{
	int rc;
	errf_t *err;
	struct json_sign_ctx *ctx = NULL;
	struct sshbuf *sigbuf = NULL, *tbsbuf;
	uint8_t *sig = NULL;
	size_t siglen;
	const char *alg = NULL;

	if (pubkey->type == KEY_RSA)
		alg = "rsa-sha2-256";

	ctx = json_sign_new();
	if (ctx == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	err = json_sign_begin(ctx, obj, subprop);
	if (err != ERRF_OK)
		goto out;

	tbsbuf = json_sign_get_tbs(ctx);

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

	err = json_sign_set_signature(ctx, sigbuf);
	if (err != ERRF_OK)
		goto out;

	err = json_sign_finish(ctx);
	ctx = NULL;

out:
	sshbuf_free(sigbuf);
	free(sig);
	json_sign_abort(ctx);
	return (err);
}

static errf_t *
piv_sign_json(struct piv_token *tkn, struct piv_slot *slot,
    const char *subprop, json_object *obj)
{
	int rc;
	errf_t *err;
	struct json_sign_ctx *ctx = NULL;
	struct sshbuf *sigbuf = NULL, *tbsbuf = NULL;
	enum sshdigest_types hashalg;
	struct sshkey *pubkey;
	uint8_t *sig = NULL;
	size_t siglen;

	pubkey = piv_slot_pubkey(slot);
	if (pubkey == NULL) {
		err = errf("NoPubKey", NULL, "Slot %02x has no public key",
		    piv_slot_id(slot));
		goto out;
	}

	hashalg = best_sign_alg_for_key(pubkey);

	ctx = json_sign_new();
	if (ctx == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	err = json_sign_begin(ctx, obj, subprop);
	if (err != ERRF_OK)
		goto out;

	tbsbuf = json_sign_get_tbs(ctx);

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

	err = json_sign_set_signature(ctx, sigbuf);
	if (err != ERRF_OK)
		goto out;

	err = json_sign_finish(ctx);
	ctx = NULL;

out:
	free(sig);
	sshbuf_free(sigbuf);
	json_sign_abort(ctx);
	return (err);
}

static errf_t *
verify_json(struct sshkey *pubkey, const char *subprop, json_object *obj)
{
	int rc;
	errf_t *err;
	struct sshbuf *sigbuf, *tbsbuf;
	struct json_sign_ctx *ctx = NULL;

	ctx = json_sign_new();
	if (ctx == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	err = json_sign_begin(ctx, obj, subprop);
	if (err != ERRF_OK)
		goto out;

	tbsbuf = json_sign_get_tbs(ctx);
	sigbuf = json_sign_get_signature(ctx);

	if (sigbuf == NULL) {
		const char *v = getenv("PIVY_CA_UNSIGNED");
		if (v == NULL ||
		    strcasecmp(v, "yes-i-really-want-no-security") != 0) {
			err = errf("InvalidSignature", NULL, "No JSON "
			    "signature policy found on CA configuration");
			goto out;
		}
		err = ERRF_OK;
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
		err = ERRF_OK;
	}

out:
	json_sign_abort(ctx);
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
	free(ca->ca_guidhex);
	ebox_free(ca->ca_pin_ebox);
	ebox_free(ca->ca_old_pin_ebox);
	ebox_free(ca->ca_backup_ebox);
	ebox_free(ca->ca_puk_ebox);
	ebox_free(ca->ca_admin_ebox);
	sshkey_free(ca->ca_cak);
	X509_NAME_free(ca->ca_dn);
	json_object_put(ca->ca_vars);
	json_object_put(ca->ca_req_vars);
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
	for (uri = ca->ca_aias; uri != NULL; uri = nuri) {
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
	json_object_put(tpl->cct_vars);
	json_object_put(tpl->cct_req_vars);
	free(tpl);
}

static errf_t *
unparse_cert_template(struct ca *ca, struct ca_cert_tpl *tpl, json_object *robj)
{
	json_object *obj, *prop;

	obj = json_object_new_object();
	VERIFY(obj != NULL);

	if (tpl->cct_help != NULL && strlen(tpl->cct_help) > 0) {
		prop = json_object_new_string(tpl->cct_help);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "help", prop);
	}

	if (tpl->cct_flags & CCTF_SELF_SIGNED) {
		prop = json_object_new_boolean(1);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "self_signed", prop);
	}
	if (tpl->cct_flags & CCTF_ALLOW_REQS) {
		prop = json_object_new_boolean(1);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "allow_reqs", prop);
	}
	if (tpl->cct_flags & CCTF_COPY_DN) {
		prop = json_object_new_boolean(1);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "copy_dn", prop);
	}
	if (tpl->cct_flags & CCTF_COPY_KP) {
		prop = json_object_new_boolean(1);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "copy_kp", prop);
	}
	if (tpl->cct_flags & CCTF_COPY_SAN) {
		prop = json_object_new_boolean(1);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "copy_san", prop);
	}
	if (tpl->cct_flags & CCTF_COPY_OTHER_EXTS) {
		prop = json_object_new_boolean(1);
		VERIFY(prop != NULL);
		json_object_object_add(obj, "copy_other_exts", prop);
	}

	prop = json_object_new_string(cert_tpl_name(tpl->cct_tpl));
	VERIFY(prop != NULL);
	json_object_object_add(obj, "template", prop);

	if (tpl->cct_vars != NULL) {
		json_object_get(tpl->cct_vars);
		json_object_object_add(obj, "variables", tpl->cct_vars);
	}
	if (tpl->cct_req_vars != NULL) {
		json_object_get(tpl->cct_req_vars);
		json_object_object_add(obj, "require_variables",
		    tpl->cct_req_vars);
	}

	json_object_object_add(robj, tpl->cct_name, obj);

	return (ERRF_OK);
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
	tpl->cct_req_vars = json_object_object_get(robj, "require_variables");
	if (tpl->cct_req_vars != NULL)
		json_object_get(tpl->cct_req_vars);

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
	json_object_put(tpl->ctst_vars);
	json_object_put(tpl->ctst_req_vars);
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
	tpl->ctst_req_vars = json_object_object_get(robj, "require_variables");
	if (tpl->ctst_req_vars != NULL)
		json_object_get(tpl->ctst_req_vars);

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
	tpl->ctt_req_vars = json_object_object_get(robj, "require_variables");
	if (tpl->ctt_req_vars != NULL)
		json_object_get(tpl->ctt_req_vars);

	tpl->ctt_next = ca->ca_token_tpls;
	if (ca->ca_token_tpls != NULL)
		ca->ca_token_tpls->ctt_prev = tpl;
	ca->ca_token_tpls = tpl;

	return (ERRF_OK);
}

static char *
calc_cert_slug(X509_NAME *subj, const STACK_OF(X509_EXTENSION) *exts,
    BIGNUM *serial)
{
	struct sshbuf *buf;
	X509_NAME_ENTRY *ent;
	ASN1_STRING *val = NULL;
	int nid;
	uint i, j, max, gmax;
	const unsigned char *p;
	int run = 0;
	char *ret;
	X509_EXTENSION *ext;
	ASN1_OBJECT *obj;
	STACK_OF(GENERAL_NAME) *gns;
	GENERAL_NAME *gn;
	void *v;
	int ptype;
	char *serialhex = NULL;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	/* First, see if we can find a commonName (CN) attribute */
	max = X509_NAME_entry_count(subj);
	for (i = 0; i < max; ++i) {
		ent = X509_NAME_get_entry(subj, i);

		obj = X509_NAME_ENTRY_get_object(ent);
		val = X509_NAME_ENTRY_get_data(ent);

		nid = OBJ_obj2nid(obj);
		if (nid == NID_commonName)
			goto done;
	}

	/* Otherwise look through extensions for a SAN */
	max = 0;
	if (exts != NULL)
		max = sk_X509_EXTENSION_num(exts);
	for (i = 0; i < max; ++i) {
		ext = (X509_EXTENSION *)sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		nid = OBJ_obj2nid(obj);
		if (nid != NID_subject_alt_name)
			continue;
		gns = X509V3_EXT_d2i(ext);
		gmax = sk_GENERAL_NAME_num(gns);

		for (j = 0; j < gmax; ++j) {
			gn = sk_GENERAL_NAME_value(gns, j);
			v = GENERAL_NAME_get0_value(gn, &ptype);
			switch (ptype) {
			case GEN_EMAIL:
			case GEN_DNS:
				val = v;
				goto done;
			}
		}
	}

done:
	VERIFY(val != NULL);
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

	serialhex = BN_bn2hex(serial);
	VERIFY(serialhex != NULL);
	VERIFY3U(strlen(serialhex), >, 9);
	serialhex[9] = '\0';
	VERIFY0(sshbuf_putf(buf, "-%s", serialhex));

	ret = sshbuf_dup_string(buf);
	sshbuf_free(buf);
	free(serialhex);
	return (ret);
}

static char *
calc_cert_slug_X509(X509 *cert)
{
	X509_NAME *subj;
	const STACK_OF(X509_EXTENSION) *exts;
	ASN1_INTEGER *asn1_serial;
	BIGNUM *serial;
	char *ret;

	asn1_serial = X509_get_serialNumber(cert);
	serial = ASN1_INTEGER_to_BN(asn1_serial, NULL);

	exts = X509_get0_extensions(cert);

	subj = X509_get_subject_name(cert);

	ret = calc_cert_slug(subj, exts, serial);

	BN_free(serial);
	return (ret);
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

static errf_t *
write_uri_array(json_object *array, struct ca_uri *head)
{
	json_object *obj;
	struct ca_uri *u;

	for (u = head; u != NULL; u = u->cu_next) {
		obj = json_object_new_string(u->cu_uri);
		VERIFY(obj != NULL);
		json_object_array_add(array, obj);
	}

	return (ERRF_OK);
}

const char *
ca_get_ebox_tpl(struct ca *ca, enum ca_ebox_type type)
{
	struct ca_ebox_tpl **ptr;
	switch (type) {
	case CA_EBOX_PIN:
	case CA_EBOX_OLD_PIN:
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
	default:
		assert(0);
		return (NULL);
	}
	if (*ptr == NULL)
		return (NULL);
	return ((*ptr)->cet_name);
}

struct ebox_tpl *
ca_get_ebox_tpl_name(struct ca *ca, const char *name)
{
	struct ca_ebox_tpl *cet;
	cet = get_ebox_tpl(&ca->ca_ebox_tpls, name, 0);
	if (cet == NULL)
		return (NULL);
	return (cet->cet_tpl);
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
	case CA_EBOX_OLD_PIN:
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
	default:
		return (errf("InvalidEboxType", NULL, "Invalid ebox type: %d",
		    type));
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
cana_initial_admin_key(struct ca_new_args *cna, enum piv_alg alg,
    const uint8_t *key, size_t keylen)
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

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".key.ebox", sizeof (fname));

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
ca_write_pukpin(struct ca *ca, enum piv_pin type, boolean_t old,
    const char *pin)
{
	struct sshbuf *buf = NULL;
	struct ebox *box = NULL;
	size_t done;
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
		if (old)
			typeslug = "old-pin";
		break;
	case PIV_PUK:
		cet = ca->ca_puk_tpl;
		typeslug = "puk";
		break;
	default:
		VERIFY(0);
		return (NULL);
	}

	err = ebox_create(cet->cet_tpl, (const uint8_t *)pin, strlen(pin),
	    NULL, 0, &box);
	if (err != ERRF_OK) {
		goto out;
	}

	err = sshbuf_put_ebox(buf, box);
	if (err != ERRF_OK)
		goto out;

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".", sizeof (fname));
	xstrlcat(fname, typeslug, sizeof (fname));
	xstrlcat(fname, ".ebox", sizeof (fname));

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

errf_t *
ca_rotate_pin(struct ca_session *sess)
{
	struct ca *ca = sess->cs_ca;
	char *newpin = NULL;
	struct ca_session_direct *csd = &sess->cs_direct;
	errf_t *err;
	boolean_t in_txn = B_FALSE;

	if (sess->cs_type != CA_SESSION_DIRECT) {
		err = errf("SessionTypeError", NULL, "A direct session (not "
		    "via pivy-agent) is required for PIN rotation");
		goto out;
	}

	if (csd->csd_pin == NULL) {
		err = errf("CAAuthError", NULL, "CA session is not "
		    "currently authenticated");
		goto out;
	}

	newpin = generate_pin();

	err = piv_txn_begin(csd->csd_token);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err, "Failed to open transaction "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}
	in_txn = B_TRUE;

	err = piv_select(csd->csd_token);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err, "Failed to select PIV applet "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_auth_key(csd->csd_token, csd->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err, "PIV CAK check failed "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_verify_pin(csd->csd_token, csd->csd_pintype, csd->csd_pin,
	    NULL, B_FALSE);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err, "Failed to verify PIN "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = ca_write_pukpin(ca, PIV_PIN, B_TRUE, csd->csd_pin);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err,
		    "Failed to write old PIN backup ebox");
		goto out;
	}

	ebox_free(ca->ca_pin_ebox);
	ca->ca_pin_ebox = NULL;

	err = ca_write_pukpin(ca, PIV_PIN, B_FALSE, newpin);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err,
		    "Failed to write new PIN ebox");
		goto out;
	}

	err = piv_change_pin(csd->csd_token, csd->csd_pintype, csd->csd_pin,
	    newpin);
	if (err != ERRF_OK) {
		err = errf("PINRotateError", err, "Failed to change PIN "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	explicit_bzero(csd->csd_pin, strlen(csd->csd_pin));
	free(csd->csd_pin);

	csd->csd_pin = newpin;
	newpin = NULL;

out:
	if (in_txn)
		piv_txn_end(csd->csd_token);
	if (newpin != NULL)
		explicit_bzero(newpin, strlen(newpin));
	free(newpin);
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
	json_object *robj = NULL, *tobj, *obj;
	errf_t *err;

	robj = json_object_new_object();
	VERIFY(robj != NULL);

	if (ca->ca_pin_tpl != NULL) {
		tobj = json_object_new_object();
		VERIFY(tobj != NULL);
		obj = json_object_new_string(ca->ca_pin_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(tobj, "template", obj);
		json_object_object_add(robj, "pin", tobj);
	}

	if (ca->ca_backup_tpl != NULL) {
		tobj = json_object_new_object();
		VERIFY(tobj != NULL);
		obj = json_object_new_string(ca->ca_backup_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(tobj, "template", obj);
		json_object_object_add(robj, "backup", tobj);
	}

	if (ca->ca_puk_tpl != NULL) {
		tobj = json_object_new_object();
		VERIFY(tobj != NULL);
		obj = json_object_new_string(ca->ca_puk_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(tobj, "template", obj);
		json_object_object_add(robj, "puk", tobj);
	}

	if (ca->ca_admin_tpl != NULL) {
		tobj = json_object_new_object();
		VERIFY(tobj != NULL);
		obj = json_object_new_string(ca->ca_admin_tpl->cet_name);
		VERIFY(obj != NULL);
		json_object_object_add(tobj, "template", obj);
		json_object_object_add(robj, "admin", tobj);
	}

	*robjp = robj;
	robj = NULL;
	err = ERRF_OK;

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
	uint sshksz = 0;
	int rc;
	size_t done;
	char *newpin = NULL, *newpuk = NULL;
	struct piv_chuid *chuid = NULL;
	struct piv_fascn *fascn = NULL;
	struct piv_pinfo *pinfo = NULL;
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
	struct sshkey *cak = NULL;
	struct cert_var_scope *scope = NULL;
	json_object *robj = NULL, *obj = NULL;
	char *dnstr = NULL;
	const char *jsonstr;
	struct ca_session sess;
	EVP_PKEY *pkey;

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
		err = errfno("mkdir", rc, "%s", path);
		goto out;
	}

	xstrlcpy(fname, path, sizeof (fname));
	xstrlcat(fname, "/pivy-ca.json", sizeof (fname));

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
	buf = sshbuf_from(ca->ca_guid, sizeof (ca->ca_guid));
	VERIFY(buf != NULL);
	ca->ca_guidhex = sshbuf_dtob16(buf);
	sshbuf_free(buf);
	buf = NULL;

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

	err = ca_write_pukpin(ca, PIV_PIN, B_FALSE, newpin);
	if (err != ERRF_OK)
		goto out;
	err = ca_write_pukpin(ca, PIV_PUK, B_FALSE, newpuk);
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
		goto out;
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
	ca->ca_pubkey = pubkey;

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

	if ((err = sshkey_to_evp_pkey(pubkey, &pkey))) {
		err = errf("CertificateError", err,
		    "Error converting pubkey to EVP_PKEY");
		goto out;
	}
	VERIFY(X509_set_pubkey(cert, pkey) == 1);
	EVP_PKEY_free(pkey);

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

	err = piv_read_cert(tkn, PIV_SLOT_SIGNATURE);
	if (err != ERRF_OK)
		goto out;

	xstrlcpy(fname, path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".crt", sizeof (fname));

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

	if ((err = sshkey_to_evp_pkey(cak, &pkey))) {
		err = errf("CertificateError", err,
		    "Error converting CAK pubkey to EVP_PKEY");
		goto out;
	}
	VERIFY(X509_set_pubkey(cert, pkey) == 1);
	EVP_PKEY_free(pkey);

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

	err = piv_read_cert(tkn, PIV_SLOT_CARD_AUTH);
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

	obj = json_object_new_string(ca->ca_guidhex);
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

	obj = json_object_new_string("1w");
	VERIFY(obj != NULL);
	json_object_object_add(robj, "crl_lifetime", obj);
	ca->ca_crl_lifetime = 7*24*3600;

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

	obj = json_object_new_object();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "require_variables", obj);

	err = piv_verify_pin(tkn, PIV_PIN, newpin, NULL, B_FALSE);
	if (err != ERRF_OK)
		goto out;

	err = piv_sign_json(tkn, caslot, "ca", robj);
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

	bzero(&sess, sizeof (sess));
	sess.cs_ca = ca;
	sess.cs_type = CA_SESSION_DIRECT;
	sess.cs_direct.csd_token = tkn;
	sess.cs_direct.csd_slot = caslot;
	sess.cs_direct.csd_cakslot = slot;
	sess.cs_direct.csd_pin = newpin;
	sess.cs_direct.csd_pintype = PIV_PIN;

	piv_txn_end(tkn);

	err = ca_log_init(ca, &sess, serial, dnstr);
	if (err != ERRF_OK)
		goto out;

	err = ca_log_new_cert(ca, &sess, "ca-cak", NULL, cert);
	if (err != ERRF_OK)
		goto out;

	*out = ca;
	ca = NULL;
	err = ERRF_OK;

out:
	if (piv_token_in_txn(tkn))
		piv_txn_end(tkn);
	sshbuf_free(buf);
	scope_free_root(scope);
	sshkey_free(cakey);
	sshkey_free(cak);
	X509_free(cert);
	OPENSSL_free(cdata);
	piv_chuid_free(chuid);
	piv_fascn_free(fascn);
	piv_pinfo_free(pinfo);
	json_object_put(robj);
	free(dnstr);
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

static errf_t *
load_ebox_file(struct ca *ca, const char *typeslug, struct ebox **outp)
{
	errf_t *err;
	char fname[PATH_MAX];
	FILE *f = NULL;
	size_t buflen;
	uint8_t *buf = NULL;
	struct sshbuf *sbuf = NULL;
	struct stat st;
	struct ebox *box = NULL;
	int rc;

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".", sizeof (fname));
	xstrlcat(fname, typeslug, sizeof (fname));
	xstrlcat(fname, ".ebox", sizeof (fname));

	f = fopen(fname, "r");
	if (f == NULL) {
		err = errf("EboxError", errfno("fopen", errno, NULL),
		    "Failed to open CA ebox file '%s' for reading",
		    fname);
		goto out;
	}

	bzero(&st, sizeof (st));
	rc = fstat(fileno(f), &st);
	if (rc != 0) {
		err = errfno("stat", errno, "on '%s'", fname);
		goto out;
	}

	if (S_ISDIR(st.st_mode) || S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)
#if defined(S_ISSOCK)
	    || S_ISSOCK(st.st_mode)
#endif
	    ) {
		err = errf("InvalidFileType", NULL, "file '%s' is not "
		    "a regular file", fname);
		goto out;
	}

	if (st.st_size < 1) {
		err = ERRF_OK;
		goto out;
	}

	buflen = st.st_size;
	buf = mmap(NULL, buflen, PROT_READ, MAP_PRIVATE, fileno(f), 0);
	if (buf == MAP_FAILED) {
		err = errf("EboxError", errfno("mmap", errno, NULL),
		    "Failed to open CA ebox file '%s' for reading",
		    fname);
		goto out;
	}

	sbuf = sshbuf_from(buf, buflen);
	if (sbuf == NULL) {
		err = errf("EboxError",
		    ssherrf("sshbuf_from", SSH_ERR_ALLOC_FAIL),
		    "Failed to open CA ebox file '%s' for reading",
		    fname);
		goto out;
	}

	err = sshbuf_get_ebox(sbuf, &box);
	if (err != ERRF_OK) {
		err = errf("EboxError", err,
		    "Failed to read CA ebox from file '%s'", fname);
		goto out;
	}

	*outp = box;
	box = NULL;

out:
	if (buf != NULL)
		munmap(buf, buflen);
	if (f != NULL)
		fclose(f);
	sshbuf_free(sbuf);
	ebox_free(box);
	return (err);
}

struct ebox *
ca_get_ebox(struct ca *ca, enum ca_ebox_type type)
{
	errf_t *err;
	struct ebox **p;
	const char *typeslug;

	switch (type) {
	case CA_EBOX_PIN:
		p = &ca->ca_pin_ebox;
		typeslug = "pin";
		break;
	case CA_EBOX_OLD_PIN:
		p = &ca->ca_old_pin_ebox;
		typeslug = "old-pin";
		break;
	case CA_EBOX_PUK:
		p = &ca->ca_puk_ebox;
		typeslug = "puk";
		break;
	case CA_EBOX_ADMIN_KEY:
		p = &ca->ca_admin_ebox;
		typeslug = "admin";
		break;
	case CA_EBOX_KEY_BACKUP:
		VERIFY(0);
		return (NULL);
	default:
		VERIFY(0);
		return (NULL);
	}

	if (*p != NULL)
		return (*p);

	err = load_ebox_file(ca, typeslug, p);
	if (err != ERRF_OK)
		return (NULL);

	return (*p);
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

	xstrlcpy(fname, path, sizeof (fname));
	xstrlcat(fname, "/pivy-ca.json", sizeof (fname));

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
		err = errf("InvalidProperty", err, "CA JSON has invalid 'dn' "
		    "property: '%s'", json_object_get_string(obj));
		goto metaerr;
	}

	ca_recalc_slug(ca);

	xstrlcpy(fname, path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".crt", sizeof (fname));

	free(buf);
	buf = NULL;

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

	rc = X509_NAME_cmp(X509_get_subject_name(ca->ca_cert), ca->ca_dn);
	if (rc != 0) {
		err = errf("NameMismatch", NULL, "CA cert DN and config DN "
		    "do not match");
		goto metaerr;
	}

	/*
	 * Use the DN from the actual cert, to make sure we encode it exactly
	 * the same way (e.g. IA5String vs UTF8String)
	 */
	X509_NAME_free(ca->ca_dn);
	ca->ca_dn = X509_NAME_dup(X509_get_subject_name(ca->ca_cert));
	VERIFY(ca->ca_dn != NULL);

	/*
	 * Check to see if the root cert has the CRL dist points extension on
	 * it: if it does, we should place the IDP extension in CRLs. Otherwise
	 * we must not insert it (OpenSSL will refuse to trust the CRLs).
	 */
	rc = X509_get_ext_by_NID(ca->ca_cert, NID_crl_distribution_points, -1);
	if (rc != -1)
		ca->ca_crls_want_idp = B_TRUE;

	err = verify_json(ca->ca_pubkey, "ca", robj);
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
	bcopy(sshbuf_ptr(sbuf), ca->ca_guid, sizeof (ca->ca_guid));
	ca->ca_guidhex = sshbuf_dtob16(sbuf);

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

	obj = json_object_object_get(robj, "aia");
	if (obj == NULL) {
		err = errf("MissingProperty", NULL, "CA JSON does not have "
		    "'aia' property");
		goto out;
	}
	err = read_uri_array(obj, &ca->ca_aias);
	if (err != ERRF_OK) {
		err = errf("InvalidProperty", err, "CA JSON has invalid "
		    "'aia' property: '%s'", json_object_get_string(obj));
		goto out;
	}

	ca->ca_crl_lifetime = 7*24*3600;
	obj = json_object_object_get(robj, "crl_lifetime");
	if (obj != NULL) {
		p = strdup(json_object_get_string(obj));
		err = parse_lifetime(p, &ca->ca_crl_lifetime);
		free(p);
		if (err != ERRF_OK) {
			err = errf("InvalidProperty", err, "CA JSON has "
			    "invalid 'crl_lifetime' property: '%s'",
			    json_object_get_string(obj));
			goto out;
		}
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

	ca->ca_slot = PIV_SLOT_SIGNATURE;
	obj = json_object_object_get(robj, "slot");
	if (obj != NULL) {
		err = piv_slotid_from_string(json_object_get_string(obj),
		    &ca->ca_slot);
		if (err != ERRF_OK) {
			err = errf("InvalidProperty", err, "CA JSON has "
			    "invalid 'slot' property: '%s'",
			    json_object_get_string(obj));
			goto out;
		}
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
		json_object_get(ca->ca_vars);
	ca->ca_req_vars = json_object_object_get(obj, "require_variables");
	if (ca->ca_req_vars != NULL)
		json_object_get(ca->ca_req_vars);

	err = ca_log_verify(ca, NULL, NULL, NULL);
	if (err != ERRF_OK)
		goto out;

	err = load_ebox_file(ca, "pin", &ca->ca_pin_ebox);
	if (err != ERRF_OK) {
		errf_free(err);
		err = ERRF_OK;
	}

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

static errf_t *
set_reqs_from_json(struct cert_var_scope *scope, json_object *obj)
{
	json_object_iter iter;
	struct cert_var *cv;
	bzero(&iter, sizeof (iter));
	json_object_object_foreachC(obj, iter) {
		if (!json_object_get_boolean(iter.val))
			continue;
		cv = scope_lookup(scope, iter.key, 0);
		if (cv == NULL)
			continue;
		cert_var_set_required(cv, REQUIRED_FOR_CERT);
		cert_var_set_required(cv, REQUIRED_FOR_CERT_REQUEST);
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

	if (ca->ca_req_vars != NULL) {
		err = set_reqs_from_json(sc, ca->ca_req_vars);
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

	if (tpl->cct_req_vars != NULL) {
		err = set_reqs_from_json(sc, tpl->cct_req_vars);
		if (err != ERRF_OK) {
			errf_free(err);
			return (NULL);
		}
	}

	return (sc);
}

errf_t *
ca_log_verify(struct ca *ca, char **final_hash, log_iter_cb_t cb, void *cookie)
{
	FILE *logf = NULL;
	char fname[PATH_MAX];
	json_object *obj = NULL, *hobj;
	struct stat st;
	int rc;
	errf_t *err;
	size_t len, pos, lineno, llen;
	char *buf = NULL;
	const char *p;
	enum json_tokener_error jerr;
	struct json_tokener *tok = NULL;
	struct sshbuf *ldigest = NULL, *tbsbuf = NULL, *hbuf = NULL;
	const char *tmp;
	uint8_t *rptr;
	size_t rlen;

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".log", sizeof (fname));

	hbuf = sshbuf_new();
	if (hbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	ldigest = sshbuf_new();
	if (ldigest == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	tbsbuf = sshbuf_new();
	if (tbsbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	logf = fopen(fname, "r");
	if (logf == NULL) {
		err = errf("LogError", errfno("fopen", errno, NULL),
		    "Failed to open CA log file '%s' for reading",
		    fname);
		goto out;
	}

	bzero(&st, sizeof (st));
	rc = fstat(fileno(logf), &st);
	if (rc != 0) {
		err = errfno("stat", errno, "on '%s'", fname);
		goto out;
	}

	if (S_ISDIR(st.st_mode) || S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)
#if defined(S_ISSOCK)
	    || S_ISSOCK(st.st_mode)
#endif
	    ) {
		err = errf("InvalidFileType", NULL, "file '%s' is not "
		    "a regular file", fname);
		goto out;
	}

	if (st.st_size < 1) {
		err = ERRF_OK;
		goto out;
	}

	len = st.st_size;
	buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fileno(logf), 0);
	if (buf == MAP_FAILED) {
		err = errf("LogError", errfno("mmap", errno, NULL),
		    "Failed to open CA log file '%s' for reading",
		    fname);
		goto out;
	}

	pos = 0;
	lineno = 1;
	while (buf[pos] == '\n' && pos < len) {
		++pos;
		++lineno;
	}
	do {
		p = &buf[pos];
		for (llen = 0; llen < len - pos; ++llen) {
			if (p[llen] == '\n')
				break;
		}
		tok = json_tokener_new();
		if (tok == NULL) {
			err = errfno("json_tokener_new", errno, NULL);
			goto out;
		}
		obj = json_tokener_parse_ex(tok, p, llen);
		jerr = json_tokener_get_error(tok);
		if (jerr != json_tokener_success) {
			err = errf("LogError",
			    jtokerrf("json_tokener_parse_ex", jerr),
			    "Failed to parse JSON object at line %zu",
			    lineno);
			goto out;
		}
		VERIFY(obj != NULL);
		if (json_tokener_get_parse_end(tok) < llen) {
			err = errf("LengthError", NULL, "JSON object at line "
			    "%zu ended after %zu bytes, expected %zu",
			    lineno, json_tokener_get_parse_end(tok), llen);
			goto out;
		}

		err = verify_json(ca->ca_pubkey, "ca", obj);
		if (err != ERRF_OK) {
			err = errf("LogError", err,
			    "Failed to verify JSON object at line %zu",
			    lineno);
			goto out;
		}

		hobj = json_object_object_get(obj, "prev_hash");

		if (hobj == NULL && sshbuf_len(ldigest) == 0)
			goto no_prev_hash;

		if (hobj == NULL ||
		    !json_object_is_type(hobj, json_type_string)) {
			err = errf("LogError", NULL,
			    "Failed to verify JSON object at line %zu: no "
			    "prev_hash property", lineno);
			goto out;
		}
		tmp = json_object_get_string(hobj);
		sshbuf_reset(hbuf);
		rc = sshbuf_b64tod(hbuf, tmp);
		if (rc != 0) {
			err = errf("LogError", ssherrf("sshbuf_b64tod", rc),
			    "Failed to verify JSON object at line %zu: "
			    "prev_hash is not a base64 string", lineno);
			goto out;
		}

		rc = sshbuf_cmp(hbuf, 0, sshbuf_ptr(ldigest),
		    sshbuf_len(ldigest));
		if (rc != 0) {
			err = errf("LogError", ssherrf("sshbuf_cmp", rc),
			    "Failed to verify JSON object at line %zu: "
			    "prev_hash mismatch", lineno);
			goto out;
		}

no_prev_hash:
		sshbuf_reset(tbsbuf);
		tmp = json_object_to_json_string_ext(obj,
		    JSON_C_TO_STRING_PLAIN);
		if ((rc = sshbuf_put_cstring8(tbsbuf, "piv-ca-log-chain")) ||
		    (rc = sshbuf_put_cstring8(tbsbuf, ca->ca_slug)) ||
		    (rc = sshbuf_put_cstring(tbsbuf, tmp))) {
			err = ssherrf("sshbuf_put_cstring", rc);
			goto out;
		}

		sshbuf_reset(ldigest);
		rlen = ssh_digest_bytes(SSH_DIGEST_SHA512);
		rc = sshbuf_reserve(ldigest, rlen, &rptr);
		if (rc != 0) {
			err = ssherrf("sshbuf_reserve", rc);
			goto out;
		}
		rc = ssh_digest_buffer(SSH_DIGEST_SHA512, tbsbuf, rptr, rlen);
		if (rc != 0) {
			err = ssherrf("ssh_digest_buffer", rc);
			goto out;
		}

		if (cb != NULL)
			cb(obj, cookie);

		json_object_put(obj);
		obj = NULL;

		json_tokener_free(tok);
		tok = NULL;

		pos += llen;
		++lineno;
		while (buf[pos] == '\n' && pos < len) {
			++pos;
			++lineno;
		}
	} while (pos < len);

	if (final_hash != NULL)
		*final_hash = sshbuf_dtob64_string(ldigest, 0);

out:
	if (buf != NULL)
		munmap(buf, len);
	if (logf != NULL)
		fclose(logf);
	if (tok != NULL)
		json_tokener_free(tok);
	json_object_put(obj);
	sshbuf_free(tbsbuf);
	sshbuf_free(hbuf);
	sshbuf_free(ldigest);
	return (err);
}

static errf_t *
ca_sign_json(struct ca *ca, struct ca_session *sess, json_object *obj)
{
	struct ca_session_agent *a = NULL;
	struct ca_session_direct *d = NULL;
	errf_t *err;
	boolean_t in_txn = B_FALSE;

	if (sess->cs_type == CA_SESSION_AGENT) {
		a = &sess->cs_agent;
		err = agent_sign_json(a->csa_fd, ca->ca_pubkey, "ca", obj);
		if (err != ERRF_OK) {
			err = errf("CASignError", err, "Failed to sign JSON "
			    "using CA key in agent '%s'", ca->ca_slug);
		}
		goto out;
	}
	VERIFY(sess->cs_type == CA_SESSION_DIRECT);
	d = &sess->cs_direct;

	err = piv_txn_begin(d->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to open transaction "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}
	in_txn = B_TRUE;

	err = piv_select(d->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to select PIV applet "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_auth_key(d->csd_token, d->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "PIV CAK check failed "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_verify_pin(d->csd_token, d->csd_pintype, d->csd_pin,
	    NULL, B_FALSE);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to verify PIN "
		    "for CA '%s' while signing JSON", ca->ca_slug);
		goto out;
	}

	err = piv_sign_json(d->csd_token, d->csd_slot, "ca", obj);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to sign JSON "
		    "with CA '%s'", ca->ca_slug);
		goto out;
	}

out:
	if (in_txn)
		piv_txn_end(d->csd_token);
	return (err);
}

static errf_t *
ca_sign_crl(struct ca *ca, struct ca_session *sess, X509_CRL *crl)
{
	struct ca_session_agent *a = NULL;
	struct ca_session_direct *d = NULL;
	errf_t *err;
	boolean_t in_txn = B_FALSE;

	if (sess->cs_type == CA_SESSION_AGENT) {
		a = &sess->cs_agent;
		err = agent_sign_crl(a->csa_fd, ca->ca_pubkey, crl);
		if (err != ERRF_OK) {
			err = errf("CASignError", err, "Failed to sign CRL "
			    "using CA key in agent '%s'", ca->ca_slug);
		}
		goto out;
	}
	VERIFY(sess->cs_type == CA_SESSION_DIRECT);
	d = &sess->cs_direct;

	if ((err = piv_txn_begin(d->csd_token)) != ERRF_OK) {
		err = errf("CASignError", err, "Failed to open transaction "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}
	in_txn = B_TRUE;

	err = piv_select(d->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to select PIV applet "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_auth_key(d->csd_token, d->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "PIV CAK check failed "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_verify_pin(d->csd_token, d->csd_pintype, d->csd_pin,
	    NULL, B_FALSE);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to verify PIN "
		    "for CA '%s' while signing cert", ca->ca_slug);
		goto out;
	}

	err = piv_sign_crl(d->csd_token, d->csd_slot, ca->ca_pubkey, crl);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to sign cert "
		    "with CA '%s'", ca->ca_slug);
		goto out;
	}

out:
	if (in_txn)
		piv_txn_end(d->csd_token);
	return (err);
}

static errf_t *
ca_add_crl_ocsp(struct ca *ca, X509 *cert)
{
	CRL_DIST_POINTS *crldps = NULL;
	DIST_POINT *dp = NULL;
	AUTHORITY_INFO_ACCESS *aia = NULL;
	ACCESS_DESCRIPTION *ad = NULL;
	struct ca_uri *uri;
	errf_t *err;
	GENERAL_NAME *nm = NULL;
	ASN1_IA5STRING *nmstr = NULL;
	int rc;

	if (ca->ca_crls != NULL) {
		crldps = CRL_DIST_POINTS_new();
		if (crldps == NULL) {
			make_sslerrf(err, "CRL_DIST_POINTS_new",
			    "adding CRL dist points");
			goto out;
		}

		dp = DIST_POINT_new();
		if (dp == NULL) {
			make_sslerrf(err, "DIST_POINT_new",
			    "adding CRL dist points");
			goto out;
		}
		dp->distpoint = DIST_POINT_NAME_new();
		if (dp->distpoint == NULL) {
			make_sslerrf(err, "DIST_POINT_NAME_new",
			    "adding CRL dist points");
			goto out;
		}
		dp->distpoint->type = 0;
		dp->distpoint->name.fullname = GENERAL_NAMES_new();
		for (uri = ca->ca_crls; uri != NULL; uri = uri->cu_next) {
			nm = GENERAL_NAME_new();
			nmstr = ASN1_IA5STRING_new();
			if (nm == NULL || nmstr == NULL) {
				make_sslerrf(err, "GENERAL_NAME_new",
				    "adding CRL dist points");
				goto out;
			}
			ASN1_STRING_set(nmstr, uri->cu_uri, -1);
			GENERAL_NAME_set0_value(nm, GEN_URI, nmstr);
			/* GENERAL_NAME_set0_value takes ownership */
			nmstr = NULL;
			rc = sk_GENERAL_NAME_push(
			    dp->distpoint->name.fullname, nm);
			if (rc == 0) {
				make_sslerrf(err, "sk_GENERAL_NAME_push",
				    "adding CRL dist points");
				goto out;
			}
			nm = NULL;
		}
		rc = sk_DIST_POINT_push(crldps, dp);
		if (rc == 0) {
			make_sslerrf(err, "sk_DIST_POINT_push",
			    "adding CRL dist points");
			goto out;
		}

		rc = X509_add1_ext_i2d(cert, NID_crl_distribution_points,
		    crldps, 0, X509V3_ADD_REPLACE);
		if (rc != 1) {
			make_sslerrf(err, "X509_add1_ext_i2d",
			    "adding CRL dist points");
			goto out;
		}
	}

	if (ca->ca_ocsps != NULL || ca->ca_aias != NULL) {
		aia = AUTHORITY_INFO_ACCESS_new();
		if (aia == NULL) {
			make_sslerrf(err, "AUTHORITY_INFO_ACCESS_new",
			    "adding OCSP AIA");
			goto out;
		}

		for (uri = ca->ca_ocsps; uri != NULL; uri = uri->cu_next) {
			nm = GENERAL_NAME_new();
			nmstr = ASN1_IA5STRING_new();
			if (nm == NULL || nmstr == NULL) {
				make_sslerrf(err, "GENERAL_NAME_new",
				    "adding OCSP AIA");
				goto out;
			}
			ASN1_STRING_set(nmstr, uri->cu_uri, -1);
			GENERAL_NAME_set0_value(nm, GEN_URI, nmstr);
			/* GENERAL_NAME_set0_value takes ownership */
			nmstr = NULL;

			ad = ACCESS_DESCRIPTION_new();
			if (ad == NULL) {
				make_sslerrf(err, "ACCESS_DESCRIPTION_new",
				    "adding OCSP AIA");
				goto out;
			}
			ad->method = OBJ_nid2obj(NID_ad_OCSP);
			if (ad->method == NULL) {
				make_sslerrf(err, "OBJ_nid2obj",
				    "adding OCSP AIA (converting OCSP NID)");
				goto out;
			}
			ad->location = nm;
			nm = NULL;
			rc = sk_ACCESS_DESCRIPTION_push(aia, ad);
			if (rc == 0) {
				make_sslerrf(err, "sk_ACCESS_DESCRIPTION_push",
				    "adding OCSP AIA");
				goto out;
			}
			ad = NULL;
		}

		for (uri = ca->ca_aias; uri != NULL; uri = uri->cu_next) {
			nm = GENERAL_NAME_new();
			nmstr = ASN1_IA5STRING_new();
			if (nm == NULL || nmstr == NULL) {
				make_sslerrf(err, "GENERAL_NAME_new",
				    "adding AIA");
				goto out;
			}
			ASN1_STRING_set(nmstr, uri->cu_uri, -1);
			GENERAL_NAME_set0_value(nm, GEN_URI, nmstr);
			/* GENERAL_NAME_set0_value takes ownership */
			nmstr = NULL;

			ad = ACCESS_DESCRIPTION_new();
			if (ad == NULL) {
				make_sslerrf(err, "ACCESS_DESCRIPTION_new",
				    "adding AIA");
				goto out;
			}
			ad->method = OBJ_nid2obj(NID_ad_ca_issuers);
			if (ad->method == NULL) {
				make_sslerrf(err, "OBJ_nid2obj",
				    "adding AIA (converting CAIssuers NID)");
				goto out;
			}
			ad->location = nm;
			nm = NULL;
			rc = sk_ACCESS_DESCRIPTION_push(aia, ad);
			if (rc == 0) {
				make_sslerrf(err, "sk_ACCESS_DESCRIPTION_push",
				    "adding AIA");
				goto out;
			}
			ad = NULL;
		}

		rc = X509_add1_ext_i2d(cert, NID_info_access, aia, 0,
		    X509V3_ADD_REPLACE);
		if (rc != 1) {
			make_sslerrf(err, "X509_add1_ext_i2d",
			    "adding OCSP dist points");
			goto out;
		}
	}

	err = ERRF_OK;

out:
	CRL_DIST_POINTS_free(crldps);
	AUTHORITY_INFO_ACCESS_free(aia);
	ACCESS_DESCRIPTION_free(ad);
	GENERAL_NAME_free(nm);
	ASN1_IA5STRING_free(nmstr);

	return (err);
}

static errf_t *
ca_sign_cert(struct ca *ca, struct ca_session *sess, X509 *cert)
{
	struct ca_session_agent *a = NULL;
	struct ca_session_direct *d = NULL;
	errf_t *err;
	boolean_t in_txn = B_FALSE;

	err = ca_add_crl_ocsp(ca, cert);
	if (err != ERRF_OK)
		goto out;

	if (sess->cs_type == CA_SESSION_AGENT) {
		a = &sess->cs_agent;
		err = agent_sign_cert(a->csa_fd, ca->ca_pubkey, cert);
		if (err != ERRF_OK) {
			err = errf("CASignError", err, "Failed to sign cert "
			    "using CA key in agent '%s'", ca->ca_slug);
		}
		goto out;
	}
	VERIFY(sess->cs_type == CA_SESSION_DIRECT);
	d = &sess->cs_direct;

	if ((err = piv_txn_begin(d->csd_token)) != ERRF_OK) {
		err = errf("CASignError", err, "Failed to open transaction "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}
	in_txn = B_TRUE;

	err = piv_select(d->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to select PIV applet "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_auth_key(d->csd_token, d->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "PIV CAK check failed "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_verify_pin(d->csd_token, d->csd_pintype, d->csd_pin,
	    NULL, B_FALSE);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to verify PIN "
		    "for CA '%s' while signing cert", ca->ca_slug);
		goto out;
	}

	err = piv_sign_cert(d->csd_token, d->csd_slot, ca->ca_pubkey, cert);
	if (err != ERRF_OK) {
		err = errf("CASignError", err, "Failed to sign cert "
		    "with CA '%s'", ca->ca_slug);
		goto out;
	}

out:
	if (in_txn)
		piv_txn_end(d->csd_token);
	return (err);
}

static void
add_timestamp(json_object *obj)
{
	struct timespec ts;
	struct tm *info;
	char tsbuf[64];
	int w;
	json_object *prop;

	VERIFY0(clock_gettime(CLOCK_REALTIME, &ts));
	info = gmtime(&ts.tv_sec);
	VERIFY(info != NULL);

	w = snprintf(tsbuf, sizeof (tsbuf),
	    "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
	    info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
	    info->tm_hour, info->tm_min, info->tm_sec, ts.tv_nsec / 1000000);
	VERIFY(w < sizeof (tsbuf));

	prop = json_object_new_string(tsbuf);
	VERIFY(prop != NULL);
	json_object_object_add(obj, "time", prop);

	prop = json_object_new_int64(ts.tv_sec);
	VERIFY(prop != NULL);
	json_object_object_add(obj, "time_secs", prop);
}

static errf_t *
ca_log_init(struct ca *ca, struct ca_session *sess, BIGNUM *ca_serial,
    const char *dnstr)
{
	json_object *robj = NULL, *obj = NULL;
	FILE *logf;
	char fname[PATH_MAX];
	errf_t *err;
	const char *line;
	size_t done;
	char *serialhex = NULL;

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".log", sizeof (fname));

	logf = fopen(fname, "w");
	if (logf == NULL) {
		err = errf("LogError", errfno("fopen", errno, NULL),
		    "Failed to open CA log file '%s' for reading",
		    fname);
		goto out;
	}

	serialhex = BN_bn2hex(ca_serial);
	VERIFY(serialhex != NULL);

	robj = json_object_new_object();
	if (robj == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	add_timestamp(robj);

	obj = json_object_new_string(dnstr);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "dn", obj);
	obj = NULL;

	obj = json_object_new_string(serialhex);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "serial", obj);
	obj = NULL;

	err = ca_sign_json(ca, sess, robj);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to sign initial CA "
		    "log entry for '%s'", ca->ca_slug);
		goto out;
	}

	line = json_object_to_json_string_ext(robj, JSON_C_TO_STRING_PLAIN);
	done = fwrite(line, 1, strlen(line), logf);
	if (done < 0) {
		err = errfno("fwrite", errno, "writing log json");
		goto out;
	} else if (done < strlen(line)) {
		err = errf("ShortWrite", NULL, "wrote %zu bytes instead of "
		    "%zu", done, strlen(line));
		goto out;
	}
	if (fputs("\n", logf) < 0) {
		err = errfno("fputs", errno, "writing log json");
		goto out;
	}

	err = ERRF_OK;

out:
	if (logf != NULL)
		fclose(logf);
	json_object_put(robj);
	json_object_put(obj);
	free(serialhex);
	return (err);
}

static errf_t *
ca_log_crl_gen(struct ca *ca, struct ca_session *sess, X509_CRL *crl, uint seq)
{
	json_object *robj = NULL, *obj = NULL;
	FILE *logf = NULL;
	char fname[PATH_MAX];
	const char *line;
	size_t done;
	errf_t *err;
	char *prev_hash = NULL;
	char *dnstr = NULL;
	const ASN1_TIME *asn1time;
	struct tm tmv;
	time_t t;
	STACK_OF(X509_REVOKED) *revoked;

	err = ca_log_verify(ca, &prev_hash, NULL, NULL);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to verify CA log "
		    "before writing new entry: '%s'", ca->ca_slug);
		goto out;
	}

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".log", sizeof (fname));

	logf = fopen(fname, "a");
	if (logf == NULL) {
		err = errf("LogError", errfno("fopen", errno, NULL),
		    "Failed to open CA log file '%s' for appending",
		    fname);
		goto out;
	}

	robj = json_object_new_object();
	if (robj == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if (prev_hash != NULL) {
		obj = json_object_new_string(prev_hash);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "prev_hash", obj);
		obj = NULL;
	}

	add_timestamp(robj);

	obj = json_object_new_string("gen_crl");
	VERIFY(obj != NULL);
	json_object_object_add(robj, "action", obj);
	obj = NULL;

	err = unparse_dn(X509_CRL_get_issuer(crl), &dnstr);
	if (err != ERRF_OK)
		goto out;

	obj = json_object_new_string(dnstr);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "dn", obj);
	obj = NULL;

	revoked = X509_CRL_get_REVOKED(crl);
	obj = json_object_new_int(sk_X509_REVOKED_num(revoked));
	VERIFY(obj != NULL);
	json_object_object_add(robj, "count", obj);
	obj = NULL;

	bzero(&tmv, sizeof (tmv));
	asn1time = X509_CRL_get0_lastUpdate(crl);
	if (!ASN1_TIME_to_tm(asn1time, &tmv)) {
		make_sslerrf(err, "ASN1_TIME_to_tm", "parsing lastUpdate "
		    "timestamp in CRL");
		goto out;
	}
	t = timegm(&tmv);
	obj = json_object_new_int64(t);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "from", obj);
	obj = NULL;

	bzero(&tmv, sizeof (tmv));
	asn1time = X509_CRL_get0_nextUpdate(crl);
	if (!ASN1_TIME_to_tm(asn1time, &tmv)) {
		make_sslerrf(err, "ASN1_TIME_to_tm", "parsing nextUpdate "
		    "timestamp in CRL");
		goto out;
	}
	t = timegm(&tmv);
	obj = json_object_new_int64(t);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "until", obj);
	obj = NULL;

	obj = json_object_new_int64(seq);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "seq", obj);
	obj = NULL;

	err = ca_sign_json(ca, sess, robj);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to sign CA "
		    "log entry for '%s' about CRL", ca->ca_slug);
		goto out;
	}

	line = json_object_to_json_string_ext(robj, JSON_C_TO_STRING_PLAIN);
	done = fwrite(line, 1, strlen(line), logf);
	if (done < 0) {
		err = errfno("fwrite", errno, "writing log json");
		goto out;
	} else if (done < strlen(line)) {
		err = errf("ShortWrite", NULL, "wrote %zu bytes instead of "
		    "%zu", done, strlen(line));
		goto out;
	}
	if (fputs("\n", logf) < 0) {
		err = errfno("fputs", errno, "writing log json");
		goto out;
	}

	err = ERRF_OK;

out:
	free(dnstr);
	free(prev_hash);
	if (logf != NULL)
		fclose(logf);
	json_object_put(obj);
	json_object_put(robj);
	return (err);
}

static errf_t *
ca_log_revoke_serial(struct ca *ca, struct ca_session *sess, BIGNUM *serial)
{
	json_object *robj = NULL, *obj = NULL;
	FILE *logf = NULL;
	char fname[PATH_MAX];
	const char *line;
	size_t done;
	errf_t *err;
	char *prev_hash = NULL;
	char *serialhex = NULL;

	err = ca_log_verify(ca, &prev_hash, NULL, NULL);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to verify CA log "
		    "before writing new entry: '%s'", ca->ca_slug);
		goto out;
	}

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".log", sizeof (fname));

	logf = fopen(fname, "a");
	if (logf == NULL) {
		err = errf("LogError", errfno("fopen", errno, NULL),
		    "Failed to open CA log file '%s' for appending",
		    fname);
		goto out;
	}

	robj = json_object_new_object();
	if (robj == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if (prev_hash != NULL) {
		obj = json_object_new_string(prev_hash);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "prev_hash", obj);
		obj = NULL;
	}

	add_timestamp(robj);

	obj = json_object_new_string("revoke_cert");
	VERIFY(obj != NULL);
	json_object_object_add(robj, "action", obj);
	obj = NULL;

	serialhex = BN_bn2hex(serial);
	VERIFY(serialhex != NULL);

	obj = json_object_new_string(serialhex);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "serial", obj);
	obj = NULL;

	err = ca_sign_json(ca, sess, robj);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to sign CA "
		    "log entry for '%s' about cert serial '%s'", ca->ca_slug,
		    serialhex);
		goto out;
	}

	line = json_object_to_json_string_ext(robj, JSON_C_TO_STRING_PLAIN);
	done = fwrite(line, 1, strlen(line), logf);
	if (done < 0) {
		err = errfno("fwrite", errno, "writing log json");
		goto out;
	} else if (done < strlen(line)) {
		err = errf("ShortWrite", NULL, "wrote %zu bytes instead of "
		    "%zu", done, strlen(line));
		goto out;
	}
	if (fputs("\n", logf) < 0) {
		err = errfno("fputs", errno, "writing log json");
		goto out;
	}

	err = ERRF_OK;

out:
	free(serialhex);
	free(prev_hash);
	if (logf != NULL)
		fclose(logf);
	json_object_put(obj);
	json_object_put(robj);
	return (err);
}

static errf_t *
ca_log_cert_action(struct ca *ca, struct ca_session *sess, const char *action,
    const char *tpl, struct cert_var_scope *scope, X509 *cert)
{
	json_object *robj = NULL, *obj = NULL;
	FILE *logf = NULL;
	char fname[PATH_MAX];
	const char *line;
	size_t done;
	errf_t *err;
	char *prev_hash = NULL;
	char *dnstr = NULL;
	ASN1_INTEGER *serialasn1;
	BIGNUM *serial = NULL;
	char *serialhex = NULL;
	const ASN1_TIME *asn1time;
	struct tm tmv;
	time_t t;

	err = ca_log_verify(ca, &prev_hash, NULL, NULL);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to verify CA log "
		    "before writing new entry: '%s'", ca->ca_slug);
		goto out;
	}

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/", sizeof (fname));
	xstrlcat(fname, ca->ca_slug, sizeof (fname));
	xstrlcat(fname, ".log", sizeof (fname));

	logf = fopen(fname, "a");
	if (logf == NULL) {
		err = errf("LogError", errfno("fopen", errno, NULL),
		    "Failed to open CA log file '%s' for appending",
		    fname);
		goto out;
	}

	robj = json_object_new_object();
	if (robj == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if (prev_hash != NULL) {
		obj = json_object_new_string(prev_hash);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "prev_hash", obj);
		obj = NULL;
	}

	add_timestamp(robj);

	obj = json_object_new_string(action);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "action", obj);
	obj = NULL;

	err = unparse_dn(X509_get_subject_name(cert), &dnstr);
	if (err != ERRF_OK)
		goto out;

	obj = json_object_new_string(dnstr);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "dn", obj);
	obj = NULL;

	if (tpl != NULL) {
		obj = json_object_new_string(tpl);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "template", obj);
		obj = NULL;
	}

	if (scope != NULL) {
		while (scope_parent(scope) != NULL)
			scope = scope_parent(scope);
		err = scope_to_json(scope, &obj);
		if (err != ERRF_OK)
			goto out;
		json_object_object_add(robj, "variables", obj);
		obj = NULL;
	}

	serialasn1 = X509_get_serialNumber(cert);
	serial = ASN1_INTEGER_to_BN(serialasn1, NULL);

	serialhex = BN_bn2hex(serial);
	VERIFY(serialhex != NULL);

	obj = json_object_new_string(serialhex);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "serial", obj);
	obj = NULL;

	bzero(&tmv, sizeof (tmv));
	asn1time = X509_get0_notAfter(cert);
	if (asn1time && ASN1_TIME_to_tm(asn1time, &tmv) == 1) {
		t = timegm(&tmv);
		obj = json_object_new_int64(t);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "expiry", obj);
		obj = NULL;
	}

	err = ca_sign_json(ca, sess, robj);
	if (err != ERRF_OK) {
		err = errf("CALogError", err, "Failed to sign CA "
		    "log entry for '%s' about cert '%s'", ca->ca_slug,
		    dnstr);
		goto out;
	}

	line = json_object_to_json_string_ext(robj, JSON_C_TO_STRING_PLAIN);
	done = fwrite(line, 1, strlen(line), logf);
	if (done < 0) {
		err = errfno("fwrite", errno, "writing log json");
		goto out;
	} else if (done < strlen(line)) {
		err = errf("ShortWrite", NULL, "wrote %zu bytes instead of "
		    "%zu", done, strlen(line));
		goto out;
	}
	if (fputs("\n", logf) < 0) {
		err = errfno("fputs", errno, "writing log json");
		goto out;
	}

	err = ERRF_OK;

out:
	free(serialhex);
	free(dnstr);
	free(prev_hash);
	if (logf != NULL)
		fclose(logf);
	json_object_put(obj);
	json_object_put(robj);
	BN_free(serial);
	return (err);
}

static errf_t *
ca_log_new_cert(struct ca *ca, struct ca_session *sess, const char *tpl,
    struct cert_var_scope *scope, X509 *cert)
{
	return (ca_log_cert_action(ca, sess, "issue_cert", tpl, scope, cert));
}

static errf_t *
ca_log_revoke_cert(struct ca *ca, struct ca_session *sess, X509 *cert)
{
	return (ca_log_cert_action(ca, sess, "revoke_cert", NULL, NULL, cert));
}

struct crl_gen_state {
	X509_CRL	*cgs_crl;
	time_t		 cgs_last;
	uint		 cgs_last_seq;
};

void
ca_generate_crl_log_iter(json_object *entry, void *cookie)
{
	struct crl_gen_state *cgs = cookie;
	json_object *obj;
	const char *v;
	time_t t;
	uint seq;
	X509_REVOKED *rev = NULL;
	BIGNUM *serial = NULL;
	ASN1_INTEGER *asn1_serial = NULL;
	ASN1_TIME *asn1_time = NULL;
	int rc;

	obj = json_object_object_get(entry, "action");
	if (obj == NULL)
		return;
	v = json_object_get_string(obj);
	if (strcmp(v, "revoke_cert") == 0) {
		obj = json_object_object_get(entry, "serial");
		VERIFY(obj != NULL);

		v = json_object_get_string(obj);
		rc = BN_hex2bn(&serial, v);
		if (rc == 0 || rc < strlen(v))
			goto revoke_out;
		asn1_serial = BN_to_ASN1_INTEGER(serial, NULL);
		if (asn1_serial == NULL)
			goto revoke_out;

		obj = json_object_object_get(entry, "time_secs");
		VERIFY(obj != NULL);
		t = (time_t)json_object_get_int64(obj);

		asn1_time = ASN1_TIME_set(NULL, t);

		rev = X509_REVOKED_new();
		VERIFY(rev != NULL);

		rc = X509_REVOKED_set_serialNumber(rev, asn1_serial);
		VERIFY(rc == 1);

		rc = X509_REVOKED_set_revocationDate(rev, asn1_time);
		VERIFY(rc == 1);

		rc = X509_CRL_add0_revoked(cgs->cgs_crl, rev);
		VERIFY(rc == 1);
		rev = NULL;

revoke_out:
		ASN1_INTEGER_free(asn1_serial);
		BN_free(serial);
		ASN1_TIME_free(asn1_time);

	} else if (strcmp(v, "gen_crl") == 0) {
		obj = json_object_object_get(entry, "until");
		VERIFY(obj != NULL);
		t = (time_t)json_object_get_int64(obj);
		if (t > cgs->cgs_last)
			cgs->cgs_last = t;

		obj = json_object_object_get(entry, "seq");
		if (obj != NULL) {
			seq = (uint)json_object_get_int64(obj);
			if (seq > cgs->cgs_last_seq)
				cgs->cgs_last_seq = seq;
		}
	}
}

errf_t *
ca_generate_crl(struct ca *ca, struct ca_session *sess, X509_CRL *crl)
{
	errf_t *err;
	int rc;
	ASN1_TIME *last = NULL, *until = NULL;
	struct timespec ts;
	struct crl_gen_state cgs;
	ASN1_INTEGER *seq_asn1 = NULL;
	BIGNUM *seq_bn = NULL;
	uint seq;
	struct sshbuf *buf = NULL;
	char *dpath = NULL, *opath = NULL;
	FILE *crlf = NULL;
	ISSUING_DIST_POINT *idp = NULL;
	struct ca_uri *uri;

	VERIFY(X509_CRL_set_version(crl, 1) == 1);
	rc = X509_CRL_set_issuer_name(crl, ca->ca_dn);
	if (rc != 1) {
		make_sslerrf(err, "X509_CRL_set_issuer_name", "setting issuer "
		    "name for CRL");
		goto out;
	}

	if (ca->ca_crls_want_idp) {
		idp = ISSUING_DIST_POINT_new();
		VERIFY(idp != NULL);

		idp->distpoint = DIST_POINT_NAME_new();
		idp->distpoint->type = 0;
		idp->distpoint->name.fullname = GENERAL_NAMES_new();
		for (uri = ca->ca_crls; uri != NULL; uri = uri->cu_next) {
			GENERAL_NAME *nm = GENERAL_NAME_new();
			ASN1_IA5STRING *nmstr = ASN1_IA5STRING_new();
			VERIFY(nm != NULL);
			VERIFY(nmstr != NULL);
			ASN1_STRING_set(nmstr, uri->cu_uri, -1);
			GENERAL_NAME_set0_value(nm, GEN_URI, nmstr);
			sk_GENERAL_NAME_push(idp->distpoint->name.fullname, nm);
		}

		rc = X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point,
		    idp, 1, 0);
		if (rc != 1) {
			make_sslerrf(err, "X509_CRL_add1_ext_i2d",
			    "adding CRL dist points");
			goto out;
		}
	}

	bzero(&cgs, sizeof (cgs));
	cgs.cgs_crl = crl;

	err = ca_log_verify(ca, NULL, ca_generate_crl_log_iter, &cgs);
	if (err != ERRF_OK)
		return (err);

	VERIFY0(clock_gettime(CLOCK_REALTIME, &ts));
	if (cgs.cgs_last == 0)
		cgs.cgs_last = ts.tv_sec;
	if (cgs.cgs_last > ts.tv_sec)
		cgs.cgs_last = ts.tv_sec;
	last = ASN1_TIME_set(NULL, cgs.cgs_last);
	until = ASN1_TIME_set(NULL, ts.tv_sec + ca->ca_crl_lifetime);
	seq = cgs.cgs_last_seq + 1;

	seq_bn = BN_new();
	VERIFY(seq_bn != NULL);
	VERIFY(BN_set_word(seq_bn, seq) == 1);
	seq_asn1 = BN_to_ASN1_INTEGER(seq_bn, NULL);
	VERIFY(seq_asn1 != NULL);

	VERIFY(X509_CRL_set1_lastUpdate(crl, last) == 1);
	VERIFY(X509_CRL_set1_nextUpdate(crl, until) == 1);

	rc = X509_CRL_add1_ext_i2d(crl, NID_crl_number, seq_asn1, 0, 0);
	if (rc != 1) {
		make_sslerrf(err, "X509_CRL_add1_ext_i2d",
		    "adding CRL sequence number");
		goto out;
	}

	VERIFY(X509_CRL_sort(crl) == 1);

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	VERIFY0(sshbuf_putf(buf, "%s/crl", ca->ca_base_path));
	dpath = sshbuf_dup_string(buf);
	rc = mkdir(dpath, 0700);
	if (rc != 0 && errno != EEXIST) {
		err = errfno("mkdir", rc, "%s", dpath);
		goto out;
	}

	sshbuf_reset(buf);
	VERIFY0(sshbuf_putf(buf, "%s/crl/%s-%06d.crl", ca->ca_base_path,
	    ca->ca_slug, seq));
	opath = sshbuf_dup_string(buf);

	crlf = fopen(opath, "w");
	if (crlf == NULL) {
		err = errfno("fopen", errno, "%s", opath);
		goto out;
	}

	err = ca_sign_crl(ca, sess, crl);
	if (err != ERRF_OK)
		goto out;

	PEM_write_X509_CRL(crlf, crl);
	fprintf(stderr, "Wrote revocation list to %s\n", opath);

	err = ca_log_crl_gen(ca, sess, crl, seq);

out:
	if (crlf != NULL)
		fclose(crlf);
	ASN1_TIME_free(last);
	ASN1_TIME_free(until);
	ASN1_INTEGER_free(seq_asn1);
	BN_free(seq_bn);
	sshbuf_free(buf);
	free(dpath);
	free(opath);
	ISSUING_DIST_POINT_free(idp);
	return (err);
}

boolean_t
ca_session_authed(struct ca_session *sess)
{
	if (sess->cs_type == CA_SESSION_AGENT) {
		int rc;
		rc = ssh_lock_agent(sess->cs_agent.csa_fd, 0, "");
		return (rc == 0);
	} else {
		return (sess->cs_direct.csd_pin != NULL);
	}
}

enum piv_pin
ca_session_auth_type(struct ca_session *sess)
{
	if (sess->cs_type == CA_SESSION_AGENT) {
		return (PIV_PIN);
	} else {
		return (piv_token_default_auth(sess->cs_direct.csd_token));
	}
}

errf_t *
ca_session_auth(struct ca_session *sess, enum piv_pin type, const char *pin)
{
	errf_t *err;
	struct ca *ca = sess->cs_ca;
	struct ca_session_agent *a = NULL;
	struct ca_session_direct *d = NULL;
	int rc;
	size_t len;
	boolean_t in_txn = B_FALSE;

	if (sess->cs_type == CA_SESSION_AGENT) {
		VERIFY(type == PIV_PIN);
		a = &sess->cs_agent;
		rc = ssh_lock_agent(a->csa_fd, 0, pin);
		if (rc != 0) {
			err = ssherrf("ssh_unlock_agent", rc);
			err = errf("CAAuthError", err, "Failed to verify PIN "
			    "for CA '%s'", ca->ca_slug);
			return (err);
		}
		return (ERRF_OK);
	}

	VERIFY(sess->cs_type == CA_SESSION_DIRECT);
	d = &sess->cs_direct;

	err = piv_txn_begin(d->csd_token);
	if (err != ERRF_OK) {
		err = errf("CAAuthError", err, "Failed to open transaction "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}
	in_txn = B_TRUE;

	err = piv_select(d->csd_token);
	if (err != ERRF_OK) {
		err = errf("CAAuthError", err, "Failed to select PIV applet "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_auth_key(d->csd_token, d->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK) {
		err = errf("CAAuthError", err, "PIV CAK check failed "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	err = piv_verify_pin(d->csd_token, type, pin, NULL, B_FALSE);
	if (err != ERRF_OK) {
		err = errf("CAAuthError", err, "Failed to verify PIN "
		    "for CA '%s'", ca->ca_slug);
		goto out;
	}

	d->csd_pintype = type;
	len = strlen(pin) + 1;
	d->csd_pin = calloc_conceal(1, len);
	strlcpy(d->csd_pin, pin, len);

out:
	if (in_txn)
		piv_txn_end(d->csd_token);
	return (err);
}

errf_t *
ca_open_session(struct ca *ca, struct ca_session **outsess)
{
	struct ca_session *sess = NULL;
	struct ca_session_agent *sa;
	struct ca_session_direct *sd;
	errf_t *err;
	int rc;
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

	sd->csd_context = piv_open();
	VERIFY(sd->csd_context != NULL);

	err = piv_establish_context(sd->csd_context, SCARD_SCOPE_SYSTEM);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to establish direct"
		    "session with CA card");
		goto out;
	}

	err = piv_find(sd->csd_context, ca->ca_guid, sizeof (ca->ca_guid),
	    &sd->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to locate CA card");
		goto out;
	}

	err = piv_txn_begin(sd->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to establish direct"
		    "session with CA card");
		goto out;
	}
	in_txn = 1;

	err = piv_select(sd->csd_token);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to establish direct"
		    "session with CA card");
		goto out;
	}

	err = piv_read_cert(sd->csd_token, PIV_SLOT_CARD_AUTH);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to establish direct"
		    "session with CA card");
		goto out;
	}

	sd->csd_cakslot = piv_get_slot(sd->csd_token, PIV_SLOT_CARD_AUTH);

	err = piv_auth_key(sd->csd_token, sd->csd_cakslot, ca->ca_cak);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to establish direct"
		    "session with CA card");
		goto out;
	}

	err = piv_read_cert(sd->csd_token, ca->ca_slot);
	if (err != ERRF_OK) {
		err = errf("CASessionError", err, "failed to establish direct"
		    "session with CA card");
		goto out;
	}

	sd->csd_slot = piv_get_slot(sd->csd_token, ca->ca_slot);

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
	ca->ca_sessions = sess;
	*outsess = sess;
	sess = NULL;
	err = ERRF_OK;

out:
	if (in_txn)
		piv_txn_end(sess->cs_direct.csd_token);
	ca_close_session(sess);
	return (err);
}

void
ca_close_session(struct ca_session *sess)
{
	if (sess == NULL)
		return;

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
		piv_close(csd->csd_context);
		if (csd->csd_pin != NULL)
			explicit_bzero(csd->csd_pin, strlen(csd->csd_pin));
		free(csd->csd_pin);

	} else {
		VERIFY(0);
	}

	free(sess);
}

errf_t *
ca_config_write(struct ca *ca, struct ca_session *sess)
{
	errf_t *err;
	json_object *robj = NULL, *obj = NULL;
	char *dnstr = NULL;
	char *crltime = NULL;
	char *slotid = NULL;
	struct sshbuf *buf = NULL;
	int rc;
	char fname[PATH_MAX];
	const char *jsonstr;
	FILE *caf = NULL;
	struct ca_cert_tpl *tpl;
	size_t done;

	robj = json_object_new_object();
	if (robj == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	err = unparse_dn(ca->ca_dn, &dnstr);
	if (err != ERRF_OK)
		goto out;
	obj = json_object_new_string(dnstr);
	if (obj == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	json_object_object_add(robj, "dn", obj);
	obj = NULL;

	obj = json_object_new_string(ca->ca_guidhex);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "guid", obj);

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
	err = write_uri_array(obj, ca->ca_crls);
	if (err != ERRF_OK)
		goto out;
	json_object_object_add(robj, "crl", obj);

	obj = json_object_new_array();
	VERIFY(obj != NULL);
	err = write_uri_array(obj, ca->ca_aias);
	if (err != ERRF_OK)
		goto out;
	json_object_object_add(robj, "aia", obj);

	crltime = unparse_lifetime(ca->ca_crl_lifetime);
	VERIFY(crltime != NULL);
	obj = json_object_new_string(crltime);
	VERIFY(obj != NULL);
	json_object_object_add(robj, "crl_lifetime", obj);

	if (ca->ca_slot != PIV_SLOT_SIGNATURE) {
		slotid = piv_slotid_to_string(ca->ca_slot);
		VERIFY(slotid != NULL);
		obj = json_object_new_string(slotid);
		VERIFY(obj != NULL);
		json_object_object_add(robj, "slot", obj);
	}

	obj = json_object_new_array();
	VERIFY(obj != NULL);
	err = write_uri_array(obj, ca->ca_ocsps);
	if (err != ERRF_OK)
		goto out;
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
	for (tpl = ca->ca_cert_tpls; tpl != NULL; tpl = tpl->cct_next) {
		err = unparse_cert_template(ca, tpl, obj);
		if (err != ERRF_OK)
			goto out;
	}
	json_object_object_add(robj, "cert_templates", obj);

	obj = json_object_new_object();
	VERIFY(obj != NULL);
	json_object_object_add(robj, "token_templates", obj);

	if (ca->ca_vars != NULL) {
		json_object_get(ca->ca_vars);
		json_object_object_add(robj, "variables", ca->ca_vars);
	}
	if (ca->ca_req_vars != NULL) {
		json_object_get(ca->ca_req_vars);
		json_object_object_add(robj, "require_variables", ca->ca_vars);
	}

	err = ca_sign_json(ca, sess, robj);
	if (err != NULL) {
		err = errf("CASignError", err, "Failed to sign CA config");
		goto out;
	}

	jsonstr = json_object_to_json_string_ext(robj, JSON_C_TO_STRING_PRETTY);

	xstrlcpy(fname, ca->ca_base_path, sizeof (fname));
	xstrlcat(fname, "/pivy-ca.json", sizeof (fname));

	caf = fopen(fname, "w");
	if (caf == NULL) {
		err = errf("MetadataError", errfno("fopen", errno, NULL),
		    "Failed to open CA metadata file '%s' for writing",
		    fname);
		goto out;
	}

	done = fwrite(jsonstr, 1, strlen(jsonstr), caf);
	if (done < 0) {
		err = errfno("fwrite", errno, "writing CA json");
		goto out;
	} else if (done < strlen(jsonstr)) {
		err = errf("ShortWrite", NULL, "wrote %zu bytes instead of "
		    "%zu", done, strlen(jsonstr));
		goto out;
	}

out:
	if (caf != NULL)
		fclose(caf);
	json_object_put(robj);
	free(dnstr);
	sshbuf_free(buf);
	free(crltime);
	free(slotid);
	return (err);
}

errf_t *
ca_cert_sign(struct ca_session *sess, struct ca_cert_tpl *tpl,
    struct cert_var_scope *certscope, EVP_PKEY *pubkey, X509 *out)
{
	return (errf("NotImplemented", NULL, "Not implemented yet."));
}

errf_t *
ca_cert_sign_req(struct ca_session *sess, struct ca_cert_tpl *tpl,
    struct cert_var_scope *certscope, X509_REQ *req, X509 *cert)
{
	struct ca *ca = sess->cs_ca;
	errf_t *err;
	EVP_PKEY *pkey;
	BIGNUM *serial = NULL;
	ASN1_INTEGER *serial_asn1 = NULL;
	char *slug = NULL, *dpath = NULL, *rpath = NULL, *cpath = NULL;
	struct sshbuf *buf;
	int rc;
	FILE *reqf = NULL, *certf = NULL;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	if (!(tpl->cct_flags & CCTF_ALLOW_REQS)) {
		err = errf("InvalidTemplateError", NULL, "CA cert template "
		    "'%s' does not allow signing cert reqs", tpl->cct_name);
		goto out;
	}

	pkey = X509_REQ_get_pubkey(req);

	err = scope_populate_req(certscope, req);
	if (err != ERRF_OK)
		goto out;

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	VERIFY(serial != NULL);
	VERIFY(BN_pseudo_rand(serial, 160, 0, 0) == 1);
	VERIFY(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);

	VERIFY(X509_set_version(cert, 2) == 1);
	VERIFY(X509_set_serialNumber(cert, serial_asn1) == 1);

	VERIFY(X509_set_pubkey(cert, pkey) == 1);

	err = cert_tpl_populate(tpl->cct_tpl, certscope, cert);
	if (err != ERRF_OK) {
		err = errf("CertTemplateError", err, "Failed to populate "
		    "cert template '%s'", tpl->cct_name);
		goto out;
	}

	VERIFY(X509_set_issuer_name(cert, ca->ca_dn));

	if (tpl->cct_flags & CCTF_COPY_OTHER_EXTS) {
		STACK_OF(X509_EXTENSION) *exts;
		X509_EXTENSION *ext;
		const ASN1_OBJECT *obj;
		uint i, max;
		int pos;

		exts = X509_REQ_get_extensions(req);
		if (exts != NULL && sk_X509_EXTENSION_num(exts) > 0) {
			max = sk_X509_EXTENSION_num(exts);
			for (i = 0; i < max; ++i) {
				ext = sk_X509_EXTENSION_value(exts, i);
				obj = X509_EXTENSION_get_object(ext);

				pos = X509_get_ext_by_OBJ(cert, obj, -1);
				if (pos == -1)
					X509_add_ext(cert, ext, -1);
			}
		}
	}

	slug = calc_cert_slug_X509(cert);
	VERIFY(slug != NULL);

	VERIFY0(sshbuf_putf(buf, "%s/%s", ca->ca_base_path, tpl->cct_name));
	dpath = sshbuf_dup_string(buf);
	sshbuf_reset(buf);
	rc = mkdir(dpath, 0700);
	if (rc != 0 && errno != EEXIST) {
		err = errfno("mkdir", rc, "%s", dpath);
		goto out;
	}

	VERIFY0(sshbuf_putf(buf, "%s/%s/%s.req", ca->ca_base_path,
	    tpl->cct_name, slug));
	rpath = sshbuf_dup_string(buf);
	sshbuf_reset(buf);

	VERIFY0(sshbuf_putf(buf, "%s/%s/%s.crt", ca->ca_base_path,
	    tpl->cct_name, slug));
	cpath = sshbuf_dup_string(buf);
	sshbuf_reset(buf);

	reqf = fopen(rpath, "w");
	if (reqf == NULL) {
		err = errfno("fopen", errno, "%s", rpath);
		goto out;
	}

	certf = fopen(cpath, "w");
	if (certf == NULL) {
		err = errfno("fopen", errno, "%s", cpath);
		goto out;
	}

	PEM_write_X509_REQ(reqf, req);
	fprintf(stderr, "Wrote request to %s\n", rpath);

	err = ca_sign_cert(ca, sess, cert);
	if (err != ERRF_OK)
		goto out;

	PEM_write_X509(certf, cert);
	fprintf(stderr, "Wrote certificate to %s\n", cpath);

	err = ca_log_new_cert(ca, sess, tpl->cct_name, certscope, cert);
	if (err != ERRF_OK)
		goto out;

	err = ERRF_OK;

out:
	if (reqf != NULL)
		fclose(reqf);
	if (certf != NULL)
		fclose(certf);
	BN_free(serial);
	sshbuf_free(buf);
	free(dpath);
	free(rpath);
	free(cpath);
	free(slug);
	ASN1_INTEGER_free(serial_asn1);
	return (err);
}

errf_t *
ca_revoke_cert(struct ca *ca, struct ca_session *sess, X509 *cert)
{
	return (ca_log_revoke_cert(ca, sess, cert));
}

errf_t *
ca_revoke_cert_serial(struct ca *ca, struct ca_session *sess, BIGNUM *serial)
{
	return (ca_log_revoke_serial(ca, sess, serial));
}

errf_t *
scope_populate_gn(struct cert_var_scope *scope, GENERAL_NAME *gn)
{
	int ptype, ttype;
	void *v;
	ASN1_IA5STRING *ia5 = NULL;
	ASN1_UTF8STRING *utf8 = NULL;
	ASN1_PRINTABLESTRING *prn = NULL;
	ASN1_STRING *str;
	ASN1_TYPE *pval;
	char vbuf[256];
	unsigned char *buf = NULL;
	const unsigned char *wp;
	const unsigned char *p;
	size_t len;
	ASN1_OBJECT *obj;
	ASN1_OBJECT *upn_obj = NULL;
	int rc;
	errf_t *err;

	upn_obj = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.3", 1);
	VERIFY(upn_obj != NULL);

	v = GENERAL_NAME_get0_value(gn, &ptype);

	switch (ptype) {
	case GEN_EMAIL:
		ia5 = v;
		p = ASN1_STRING_get0_data(ia5);
		len = ASN1_STRING_length(ia5);
		VERIFY3U(len, <, sizeof (vbuf));
		bcopy(p, vbuf, len);
		vbuf[len] = '\0';
		ia5 = NULL;

		err = scope_set(scope, "req_email", vbuf);
		goto out;

	case GEN_DNS:
		ia5 = v;
		p = ASN1_STRING_get0_data(ia5);
		len = ASN1_STRING_length(ia5);
		VERIFY3U(len, <, sizeof (vbuf));
		bcopy(p, vbuf, len);
		vbuf[len] = '\0';
		ia5 = NULL;

		err = scope_set(scope, "req_dns", vbuf);
		goto out;
	}

	if (ptype != GEN_OTHERNAME) {
		err = ERRF_OK;
		goto out;
	}

	GENERAL_NAME_get0_otherName(gn, &obj, &pval);

	if (OBJ_cmp(obj, upn_obj) == 0) {
		ttype = ASN1_TYPE_get(pval);

		rc = i2d_ASN1_TYPE(pval, &buf);
		if (rc < 0) {
			make_sslerrf(err, "i2d_ASN1_TYPE", "while encoding");
			goto out;
		}
		len = rc;
		wp = buf;

		switch (ttype) {
		case V_ASN1_PRINTABLESTRING:
			prn = d2i_ASN1_PRINTABLESTRING(NULL, &wp, len);
			str = (ASN1_STRING *)prn;
			break;
		case V_ASN1_IA5STRING:
			ia5 = d2i_ASN1_IA5STRING(NULL, &wp, len);
			str = (ASN1_STRING *)ia5;
			break;
		case V_ASN1_UTF8STRING:
			utf8 = d2i_ASN1_UTF8STRING(NULL, &wp, len);
			str = (ASN1_STRING *)utf8;
			break;
		default:
			err = ERRF_OK;
			goto out;
		}

		p = ASN1_STRING_get0_data(str);
		len = ASN1_STRING_length(str);
		VERIFY3U(len, <, sizeof (vbuf));
		bcopy(p, vbuf, len);
		vbuf[len] = '\0';

		err = scope_set(scope, "req_upn", vbuf);
		goto out;
	} else {
		err = ERRF_OK;
	}

out:
	OPENSSL_free(buf);
	ASN1_OBJECT_free(upn_obj);
	ASN1_PRINTABLESTRING_free(prn);
	ASN1_IA5STRING_free(ia5);
	ASN1_UTF8STRING_free(utf8);
	return (err);
}

errf_t *
scope_populate_req(struct cert_var_scope *scope, X509_REQ *req)
{
	X509_NAME *subj;
	char *dnstr = NULL;
	errf_t *err;
	int rc;
	const unsigned char *p;
	size_t len;
	char nmbuf[128], kbuf[128], vbuf[256];
	uint i, max;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ext;
	const ASN1_OBJECT *obj;
	X509_NAME_ENTRY *ent;
	ASN1_STRING *val;
	int nid;
	uint nms, j;
	const char *name;
	const char *names[3];
	ASN1_OBJECT *sid_obj = NULL;

	sid_obj = OBJ_txt2obj("1.3.6.1.4.1.311.25.2", 1);
	VERIFY(sid_obj != NULL);

	subj = X509_REQ_get_subject_name(req);

	err = unparse_dn(subj, &dnstr);
	if (err != ERRF_OK)
		goto out;
	err = scope_set(scope, "req_dn", dnstr);
	if (err != ERRF_OK)
		goto out;

	max = X509_NAME_entry_count(subj);
	for (i = 0; i < max; ++i) {
		ent = X509_NAME_get_entry(subj, i);
		obj = X509_NAME_ENTRY_get_object(ent);
		val = X509_NAME_ENTRY_get_data(ent);

		nms = 0;

		nid = OBJ_obj2nid(obj);
		if (nid != NID_undef) {
			name = OBJ_nid2sn(nid);
			if (name != NULL)
				names[nms++] = name;
			name = OBJ_nid2ln(nid);
			if (name != NULL)
				names[nms++] = name;
		}
		if (nms == 0) {
			rc = OBJ_obj2txt(nmbuf, sizeof (nmbuf), obj, 0);
			if (rc == -1) {
				make_sslerrf(err, "OBJ_obj2txt", "Failed to "
				    "convert DN entry %u", i);
				return (err);
			}
			names[nms++] = nmbuf;
		}

		p = ASN1_STRING_get0_data(val);
		len = ASN1_STRING_length(val);
		VERIFY3U(len, <, sizeof (vbuf));
		bcopy(p, vbuf, len);
		vbuf[len] = '\0';

		for (j = 0; j < nms; ++j) {
			xstrlcpy(kbuf, "req_", sizeof (kbuf));
			xstrlcat(kbuf, names[j], sizeof (kbuf));

			err = scope_set(scope, kbuf, vbuf);
			if (err != ERRF_OK)
				goto out;
		}
	}

	exts = X509_REQ_get_extensions(req);
	if (exts != NULL && sk_X509_EXTENSION_num(exts) > 0) {
		max = sk_X509_EXTENSION_num(exts);
		for (i = 0; i < max; ++i) {
			ext = sk_X509_EXTENSION_value(exts, i);
			obj = X509_EXTENSION_get_object(ext);
			nid = OBJ_obj2nid(obj);
			if (nid == NID_subject_alt_name) {
				STACK_OF(GENERAL_NAME) *gns;
				uint gmax;

				gns = X509V3_EXT_d2i(ext);
				gmax = sk_GENERAL_NAME_num(gns);

				for (j = 0; j < gmax; ++j) {
					GENERAL_NAME *gn;
					gn = sk_GENERAL_NAME_value(gns, j);
					err = scope_populate_gn(scope, gn);
					if (err != ERRF_OK)
						goto out;
				}
			} else if (OBJ_cmp(obj, sid_obj) == 0) {
				val = X509_EXTENSION_get_data(ext);
				p = ASN1_STRING_get0_data(val);
				len = ASN1_STRING_length(val);
				VERIFY3U(len, <, sizeof (vbuf));
				bcopy(p, vbuf, len);
				vbuf[len] = '\0';

				err = scope_set(scope, "req_sid", vbuf);
				if (err != ERRF_OK)
					goto out;
			}
		}
	}

out:
	free(dnstr);
	ASN1_OBJECT_free(sid_obj);
	return (err);
}

uint
ca_crl_uri_count(const struct ca *ca)
{
	uint i = 0;
	const struct ca_uri *uri;
	for (uri = ca->ca_crls; uri != NULL; uri = uri->cu_next)
		++i;
	return (i);
}
const char *
ca_crl_uri(const struct ca *ca, uint index)
{
	uint i = 0;
	const struct ca_uri *uri;
	for (uri = ca->ca_crls; uri != NULL; uri = uri->cu_next) {
		if (i++ == index)
			return (uri->cu_uri);
	}
	return (NULL);
}
errf_t *
ca_crl_uri_remove(struct ca *ca, const char *uri)
{
	return (errf("NotImplemented", NULL, "Not implemented"));
}
errf_t *
ca_crl_uri_add(struct ca *ca, const char *uri)
{
	return (errf("NotImplemented", NULL, "Not implemented"));
}

uint
ca_ocsp_uri_count(const struct ca *ca)
{
	uint i = 0;
	const struct ca_uri *uri;
	for (uri = ca->ca_ocsps; uri != NULL; uri = uri->cu_next)
		++i;
	return (i);
}
const char *
ca_ocsp_uri(const struct ca *ca, uint index)
{
	uint i = 0;
	const struct ca_uri *uri;
	for (uri = ca->ca_ocsps; uri != NULL; uri = uri->cu_next) {
		if (i++ == index)
			return (uri->cu_uri);
	}
	return (NULL);
}
errf_t *
ca_ocsp_uri_remove(struct ca *ca, const char *uri)
{
	return (errf("NotImplemented", NULL, "Not implemented"));
}
errf_t *
ca_ocsp_uri_add(struct ca *ca, const char *uri)
{
	return (errf("NotImplemented", NULL, "Not implemented"));
}

uint
ca_aia_uri_count(const struct ca *ca)
{
	uint i = 0;
	const struct ca_uri *uri;
	for (uri = ca->ca_aias; uri != NULL; uri = uri->cu_next)
		++i;
	return (i);
}
const char *
ca_aia_uri(const struct ca *ca, uint index)
{
	uint i = 0;
	const struct ca_uri *uri;
	for (uri = ca->ca_aias; uri != NULL; uri = uri->cu_next) {
		if (i++ == index)
			return (uri->cu_uri);
	}
	return (NULL);
}
errf_t *
ca_aia_uri_remove(struct ca *ca, const char *uri)
{
	return (errf("NotImplemented", NULL, "Not implemented"));
}
errf_t *
ca_aia_uri_add(struct ca *ca, const char *uri)
{
	return (errf("NotImplemented", NULL, "Not implemented"));
}

