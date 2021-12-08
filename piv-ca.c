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

enum vvtype {
	VV_STRING,
	VV_VAR
};

struct varval {
	struct varval 		*vv_next;
	enum vvtype		 vv_type;
	union {
		char		*vv_string;
		struct cert_var	*vv_var;
	};
};

static struct varval *varval_parse(const char *);
static void varval_free(struct varval *);
static char *varval_unparse(const struct varval *);

enum req_flags {
	RQF_CERT		= (1<<0),
	RQF_CERT_REQ		= (1<<1)
};

struct param {
	const char	*cp_name;
	uint		 cp_flags;
	const char	*cp_help;
};

struct cert_var_scope {
	struct cert_var_scope	*cvs_parent;
	struct cert_var_scope	*cvs_children;
	struct cert_var_scope	*cvs_next;
	struct cert_var		*cvs_vars;
};

struct cert_var {
	struct cert_var_scope	*cv_scope;
	struct cert_var		*cv_next;
	struct cert_var		*cv_parent;
	char			*cv_name;
	char			*cv_help;
	uint			 cv_flags;
	struct varval		*cv_value;
};

struct cert_tpl {
	const char	*ct_name;
	const char	*ct_help;
	struct param	 ct_params[8];
	errf_t		*(*ct_populate)(struct cert_var_scope *, X509 *);
	errf_t		*(*ct_populate_req)(struct cert_var_scope *, X509_REQ *);
};

struct ca_uri {
	struct ca_uri		*cu_next;
	char			*cu_uri;
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

	struct ebox_tpl		*ca_pin_tpl;
	struct ebox_tpl		*ca_backup_tpl;
	struct ebox_tpl		*ca_puk_tpl;
	struct ebox_tpl		*ca_admin_tpl;
	struct ebox_tpl		*ca_seqbase_tpl;

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
	struct piv_token	*csd_all_tokens;
	struct piv_token	*csd_token;
	struct piv_slot		*csd_cakslot;
	struct piv_slot		*csd_slot;
};
struct ca_session {
	struct ca_session	*cs_prev;
	struct ca_session	*cs_next;
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

static struct cert_var *get_or_define_empty_var(struct cert_var_scope *,
    const char *, const char *, uint);
static errf_t *cert_var_eval_into(struct cert_var *, struct sshbuf *);
static struct cert_var *add_undefined_deps(struct cert_var *, struct cert_var *);
static struct cert_var *cert_var_clone(struct cert_var *);
static struct cert_var *find_var(struct cert_var *, const char *);

static errf_t *load_ossl_config(const char *section,
    struct cert_var_scope *cs, CONF **out);

static errf_t *agent_sign_json(int fd, struct sshkey *pubkey, json_object *obj);
static errf_t *piv_sign_json(struct piv_token *tkn, struct piv_slot *slot,
    json_object *obj);
static errf_t *verify_json(struct sshkey *pubkey, json_object *obj);

static errf_t *read_text_file(const char *path, char **out, size_t *outlen);
static errf_t *validate_cstring(const char *buf, size_t len, size_t maxlen);

static errf_t *agent_sign_cert(int fd, struct sshkey *pubkey, X509 *cert);

#define	PARAM_DN	{ "dn", RQF_CERT | RQF_CERT_REQ, \
    "Distinguished name (e.g. 'cn=foo, o=company, c=AU')" }
#define	PARAM_LIFETIME	{ "lifetime", RQF_CERT, \
    "Certificate lifetime in seconds (or use unit suffixes 'h', 'd', 'w', 'y')" }
#define	PARAM_AD_UPN	{ "ad_upn", 0, \
    "Active Directory UPN (e.g. 'foobar@domain.com')" }
#define	PARAM_KRB5_PN	{ "krb5_principal", 0, \
    "Kerberos V principal name (e.g. 'user/admin@REALM')" }

static errf_t *populate_user_auth(struct cert_var_scope *, X509 *);
static errf_t *populate_user_key_mgmt(struct cert_var_scope *, X509 *);
static errf_t *populate_user_email(struct cert_var_scope *, X509 *);
static errf_t *populate_computer_auth(struct cert_var_scope *, X509 *);
static errf_t *populate_code_signing(struct cert_var_scope *, X509 *);
static errf_t *populate_ca(struct cert_var_scope *, X509 *);

static errf_t *rpopulate_user_auth(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_user_key_mgmt(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_user_email(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_computer_auth(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_code_signing(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_ca(struct cert_var_scope *, X509_REQ *);

struct cert_tpl cert_templates[] = {
	{
		.ct_name = "user-auth",
		.ct_help = "User auth certificate",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			PARAM_AD_UPN,
			PARAM_KRB5_PN,
			{ NULL }
		},
		.ct_populate = populate_user_auth,
		.ct_populate_req = rpopulate_user_auth
	},
	{
		.ct_name = "user-key-mgmt",
		.ct_help = "User certificate for key management (e.g. "
		    "deriving symmetric keys). If ad_upn is given, "
		    "also useable for Microsoft EFS",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			PARAM_AD_UPN,
			{ NULL }
		},
		.ct_populate = populate_user_key_mgmt,
		.ct_populate_req = rpopulate_user_key_mgmt
	},
	{
		.ct_name = "user-email",
		.ct_help = "User certificate for encrypting/signing email "
		    "using S/MIME",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			{ "email", RQF_CERT | RQF_CERT_REQ, "E-mail address" },
			{ NULL }
		},
		.ct_populate = populate_user_email,
		.ct_populate_req = rpopulate_user_email
	},
	{
		.ct_name = "computer-auth",
		.ct_help = "Computer auth certificate, for a TLS server or "
		    "if ad_upn or krb5_principal are set, a KDC or MS AD DC",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			{ "dns_name", RQF_CERT | RQF_CERT_REQ, "DNS domain name" },
			PARAM_AD_UPN,
			PARAM_KRB5_PN,
			{ NULL }
		},
		.ct_populate = populate_computer_auth,
		.ct_populate_req = rpopulate_computer_auth
	},
	{
		.ct_name = "code-signing",
		.ct_help = "Code signing certificate",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			PARAM_AD_UPN,
			PARAM_KRB5_PN,
			{ "email", 0, "E-mail address" },
			{ NULL }
		},
		.ct_populate = populate_code_signing,
		.ct_populate_req = rpopulate_code_signing
	},
	{
		.ct_name = "ca",
		.ct_help = "Certification authority",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			{ "ext_key_usage", 0, "Extended key usage constraint" },
			{ "path_len", 0, "Maximum CA path length" },
			{ "name_constraints", 0,
			    "Name constraints (OpenSSL config expression)" },
			{ "openssl_config_file", 0, "Path to openssl.cnf" },
			{ NULL }
		},
		.ct_populate = populate_ca,
		.ct_populate_req = rpopulate_ca
	},
	{
		.ct_name = NULL
	}
};

const struct cert_tpl *
cert_tpl_find(const char *name)
{
	const struct cert_tpl *tpl = cert_templates;
	for (; tpl->ct_name != NULL; ++tpl) {
		if (strcmp(tpl->ct_name, name) == 0)
			return (tpl);
	}
	return (NULL);
}

const struct cert_tpl *
cert_tpl_next(const struct cert_tpl *tpl)
{
	++tpl;
	if (tpl->ct_name == NULL)
		return (NULL);
	return (tpl);
}

const char *
cert_tpl_name(const struct cert_tpl *tpl)
{
	return (tpl->ct_name);
}

const char *
cert_tpl_help(const struct cert_tpl *tpl)
{
	return (tpl->ct_help);
}

struct cert_var *
cert_var_next(struct cert_var *cv)
{
	return (cv->cv_next);
}

const char *
cert_var_name(const struct cert_var *cv)
{
	return (cv->cv_name);
}

const char *
cert_var_help(const struct cert_var *cv)
{
	return (cv->cv_help);
}

char *
cert_var_raw_value(const struct cert_var *cv)
{
	if (cv->cv_value == NULL)
		return (NULL);
	return (varval_unparse(cv->cv_value));
}

int
cert_var_required(const struct cert_var *cv, enum requirement_type rt)
{
	switch (rt) {
	case REQUIRED_FOR_CERT:
		return ((cv->cv_flags & RQF_CERT) != 0);
	case REQUIRED_FOR_CERT_REQUEST:
		return ((cv->cv_flags & RQF_CERT_REQ) != 0);
	default:
		return (0);
	}
}

void
cert_var_set_required(struct cert_var *cv0, enum requirement_type rt)
{
	uint nflags = cv0->cv_flags;
	struct cert_var *cv;
	struct varval *vv;

	VERIFY(cv0->cv_scope != NULL);

	switch (rt) {
	case REQUIRED_FOR_CERT:
		nflags |= RQF_CERT;
		break;
	case REQUIRED_FOR_CERT_REQUEST:
		nflags |= RQF_CERT_REQ;
		break;
	default:
		return;
	}

	if (cv0->cv_flags == nflags)
		return;

	for (cv = cv0; cv != NULL; cv = cv->cv_parent)
		cv->cv_flags |= nflags;

	cv = cv0;
	while (cv->cv_value == NULL && cv->cv_parent != NULL)
		cv = cv->cv_parent;
	for (vv = cv->cv_value; vv != NULL; vv = vv->vv_next) {
		if (vv->vv_type == VV_VAR) {
			cert_var_set_required(vv->vv_var, rt);
		}
	}
}

static void
cert_var_free(struct cert_var *cv)
{
	free(cv->cv_name);
	free(cv->cv_help);
	varval_free(cv->cv_value);
}

static void
cert_var_free_chain(struct cert_var *cv)
{
	struct cert_var *next;
	for (; cv != NULL; cv = next) {
		next = cv->cv_next;
		cert_var_free(cv);
	}
}

void
cert_var_free_all(struct cert_var *cv)
{
	VERIFY(cv->cv_scope == NULL);
	cert_var_free_chain(cv);
}

struct cert_var *
cert_tpl_vars(const struct cert_tpl *tpl)
{
	struct cert_var *cv, *cv0 = NULL;
	const struct param *p;
	for (p = &tpl->ct_params[0]; p->cp_name != NULL; ++p) {
		cv = calloc(1, sizeof(struct cert_var));
		cv->cv_name = strdup(p->cp_name);
		if (p->cp_help != NULL)
			cv->cv_help = strdup(p->cp_help);
		cv->cv_flags = p->cp_flags;
		cv->cv_next = cv0;
		cv0 = cv;
	}
	return (cv0);
}

struct cert_var_scope *
scope_parent(struct cert_var_scope *scope)
{
	return (scope->cvs_parent);
}

struct cert_var_scope *
scope_new_root(void)
{
	return (scope_new_empty(NULL));
}

struct cert_var_scope *
scope_new_empty(struct cert_var_scope *parent)
{
	struct cert_var_scope *cvs;

	cvs = calloc(1, sizeof (struct cert_var_scope));
	VERIFY(cvs != NULL);
	cvs->cvs_parent = parent;

	if (parent != NULL) {
		cvs->cvs_next = parent->cvs_children;
		parent->cvs_children = cvs;
	}

	return (cvs);
}

struct cert_var_scope *
scope_new_for_tpl(struct cert_var_scope *parent, const struct cert_tpl *tpl)
{
	struct cert_var_scope *cvs;
	const struct param *p;

	cvs = scope_new_empty(parent);
	for (p = &tpl->ct_params[0]; p->cp_name != NULL; ++p) {
		(void) get_or_define_empty_var(cvs, p->cp_name, p->cp_help,
		    p->cp_flags);
	}

	return (cvs);
}

struct cert_var *
scope_lookup(struct cert_var_scope *cvs, const char *name, int undef)
{
	struct cert_var *cv;

	cv = get_or_define_empty_var(cvs, name, NULL, 0);
	if (undef)
		return (cv);
	if (cv->cv_value == NULL)
		return (NULL);
	return (cv);
}

void
cert_var_set_help(struct cert_var *cv, const char *help)
{
	VERIFY(cv->cv_scope != NULL);
	free(cv->cv_help);
	cv->cv_help = strdup(help);
}

errf_t *
cert_var_set(struct cert_var *var, const char *value)
{
	struct varval *vv;
	struct cert_var *cv;

	VERIFY(var->cv_scope != NULL);

	vv = varval_parse(value);
	if (vv == NULL) {
		return (errf("SyntaxError", NULL, "Failed to parse variable "
		    "value for %s: '%s'", var->cv_name, value));
	}

	varval_free(var->cv_value);
	var->cv_value = vv;

	for (vv = var->cv_value; vv != NULL; vv = vv->vv_next) {
		if (vv->vv_type == VV_VAR) {
			cv = get_or_define_empty_var(var->cv_scope,
			    vv->vv_string, NULL, var->cv_flags);
			vv->vv_var = cv;
		}
	}

	return (ERRF_OK);
}

errf_t *
scope_set(struct cert_var_scope *cvs, const char *name, const char *value)
{
	struct cert_var *cv, *var = NULL;
	struct varval *vv;

	vv = varval_parse(value);
	if (vv == NULL) {
		return (errf("SyntaxError", NULL, "Failed to parse variable "
		    "value for %s: '%s'", name, value));
	}

	var = get_or_define_empty_var(cvs, name, NULL, 0);

	varval_free(var->cv_value);
	var->cv_value = vv;

	for (vv = var->cv_value; vv != NULL; vv = vv->vv_next) {
		if (vv->vv_type == VV_VAR) {
			cv = get_or_define_empty_var(cvs, vv->vv_string,
			    NULL, var->cv_flags);
			vv->vv_var = cv;
		}
	}

	return (ERRF_OK);
}

errf_t *
scope_eval(struct cert_var_scope *cvs, const char *name, char **out)
{
	struct cert_var *cv;
	cv = scope_lookup(cvs, name, 1);
	return (cert_var_eval(cv, out));
}

void
scope_free_root(struct cert_var_scope *rcvs)
{
	struct cert_var_scope *cvs, *ncvs;
	VERIFY(rcvs->cvs_parent == NULL);
	cert_var_free_chain(rcvs->cvs_vars);
	for (cvs = rcvs->cvs_children; cvs != NULL; cvs = ncvs) {
		ncvs = cvs->cvs_next;
		cert_var_free_chain(cvs->cvs_vars);
		free(cvs);
	}
	free(rcvs);
}

errf_t *
cert_var_eval(struct cert_var *var, char **out)
{
	struct sshbuf *buf;
	errf_t *err;

	VERIFY(var->cv_scope != NULL);

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	err = cert_var_eval_into(var, buf);
	if (err != ERRF_OK) {
		sshbuf_free(buf);
		return (err);
	}

	*out = sshbuf_dup_string(buf);
	sshbuf_free(buf);
	return (ERRF_OK);
}

errf_t *
cert_tpl_populate(const struct cert_tpl *tpl, struct cert_var_scope *cvs,
    X509 *cert)
{
	return (tpl->ct_populate(cvs, cert));
}

errf_t *
cert_tpl_populate_req(const struct cert_tpl *tpl, struct cert_var_scope *cvs,
    X509_REQ *req)
{
	return (tpl->ct_populate_req(cvs, req));
}

struct cert_var *
scope_all_vars(struct cert_var_scope *cvs)
{
	return (cvs->cvs_vars);
}

struct cert_var *
scope_undef_vars(struct cert_var_scope *cvs)
{
	struct cert_var *cv, *rcv = NULL;

	for (cv = cvs->cvs_vars; cv != NULL; cv = cv->cv_next)
		rcv = add_undefined_deps(cv, rcv);

	return (rcv);
}

static struct cert_var *
cert_var_clone(struct cert_var *cv)
{
	struct cert_var *rcv;
	rcv = calloc(1, sizeof (struct cert_var));
	VERIFY(rcv != NULL);
	rcv->cv_name = strdup(cv->cv_name);
	if (cv->cv_help != NULL)
		rcv->cv_help = strdup(cv->cv_help);
	rcv->cv_flags = cv->cv_flags;
	return (rcv);
}

static struct cert_var *
add_undefined_deps(struct cert_var *cv, struct cert_var *rcv0)
{
	struct varval *vv;
	struct cert_var *rcv;

	while (cv->cv_value == NULL && cv->cv_parent != NULL)
		cv = cv->cv_parent;

	if (cv->cv_value == NULL) {
		rcv = find_var(rcv0, cv->cv_name);
		if (rcv == NULL) {
			rcv = cert_var_clone(cv);
			rcv->cv_next = rcv0;
			rcv0 = rcv;
		}
		return (rcv0);
	}

	for (vv = cv->cv_value; vv != NULL; vv = vv->vv_next) {
		if (vv->vv_type == VV_VAR) {
			rcv0 = add_undefined_deps(vv->vv_var, rcv0);
		}
	}

	return (rcv0);
}

static errf_t *
add_dn_component(const char *attr, const char *val, X509_NAME *name)
{
	int rc, nid;
	errf_t *err;
	char *upattr;
	uint i;

	nid = OBJ_txt2nid(attr);
	if (nid == NID_undef) {
		upattr = calloc(strlen(attr) + 1, 1);
		for (i = 0; attr[i] != '\0'; ++i)
			upattr[i] = toupper(attr[i]);
		nid = OBJ_txt2nid(upattr);
		free(upattr);
	}
	if (nid == NID_undef) {
		return (errf("UnknownAttributeError", NULL, "Unknown or "
		    "invalid attribute in DN: '%s'", attr));
	}

	rc = X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
	    (unsigned char *)val, -1, -1, 0);
	if (rc != 1) {
		make_sslerrf(err, "X509_NAME_add_entry_by_NID", "adding DN "
		    "attribute '%s'", attr);
		return (err);
	}

	return (ERRF_OK);
}

static char
from_hex_char(char v)
{
	if (v >= 'a' && v <= 'f')
		return (0xa + (v - 'a'));
	if (v >= 'A' && v <= 'F')
		return (0xa + (v - 'A'));
	if (v >= '0' && v <= '9')
		return (v - '0');
	return (0);
}

errf_t *
unparse_dn(X509_NAME *name, char **out)
{
	struct sshbuf *buf;
	uint i, j, max;
	char nmbuf[128];
	int rc;
	const unsigned char *p;
	errf_t *err;

	buf = sshbuf_new();
	if (buf == NULL)
		return (errfno("sshbuf_new", errno, NULL));

	max = X509_NAME_entry_count(name);
	for (i = 0; i < max; ++i) {
		X509_NAME_ENTRY *ent = X509_NAME_get_entry(name, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ent);
		ASN1_STRING *val = X509_NAME_ENTRY_get_data(ent);

		rc = OBJ_obj2txt(nmbuf, sizeof (nmbuf), obj, 0);
		if (rc == -1) {
			make_sslerrf(err, "OBJ_obj2txt", "Failed to convert "
			    "DN entry %u", i);
			sshbuf_free(buf);
			return (err);
		}

		VERIFY0(sshbuf_put(buf, nmbuf, strlen(nmbuf)));
		VERIFY0(sshbuf_put_u8(buf, '='));

		p = ASN1_STRING_get0_data(val);
		for (j = 0; j < ASN1_STRING_length(val); ++j) {
			char c = p[j];
			switch (c) {
			case ',':
			case '=':
				VERIFY0(sshbuf_put_u8(buf, '\\'));
				break;
			case '\t':
				VERIFY0(sshbuf_put_u8(buf, '\\'));
				c = 't';
				break;
			case '\n':
				VERIFY0(sshbuf_put_u8(buf, '\\'));
				c = 'n';
				break;
			}
			VERIFY0(sshbuf_put_u8(buf, c));
		}

		if (i + 1 < max) {
			VERIFY0(sshbuf_put_u8(buf, ','));
			VERIFY0(sshbuf_put_u8(buf, ' '));
		}
	}

	*out = sshbuf_dup_string(buf);
	sshbuf_free(buf);
	return (ERRF_OK);
}

errf_t *
parse_dn(const char *dnstr, X509_NAME *name)
{
	const char *p, *lp, *pp;
	struct sshbuf *buf;
	char *attr = NULL, *val = NULL;
	char v;
	errf_t *err;

	buf = sshbuf_new();
	if (buf == NULL)
		return (errfno("sshbuf_new", errno, NULL));

	for (lp = (p = dnstr); *p != '\0'; ++p) {
		switch (*p) {
		case '\\':
			VERIFY0(sshbuf_put(buf, lp, (p - lp)));
			v = *(++p);
			if (v == 'n') {
				v = '\n';
			} else if ((v >= 'a' && v <= 'f') ||
			    (v >= 'A' && v <= 'F') ||
			    (v >= '0' && v <= '9')) {
				v = from_hex_char(v);
				v <<= 4;
				v |= from_hex_char(*(++p));
				if (*p == '\0') {
					sshbuf_free(buf);
					return (errf("SyntaxError", NULL,
					    "Reached end of string while "
					    "processing hex escape in DN near "
					    "'%s'", lp));
				}
			}
			VERIFY0(sshbuf_put_u8(buf, v));
			lp = ++p;
			break;
		case '=':
			if (attr != NULL) {
				sshbuf_free(buf);
				return (errf("SyntaxError", NULL, "Unexpected "
				    "EQUALS in DN at '%s'", p));
			}
			/* Trim any trailing whitespace from the attr */
			pp = p;
			while (*(pp - 1) == ' ' || *(pp - 1) == '\t')
				--pp;

			VERIFY0(sshbuf_put(buf, lp, (pp - lp)));
			lp = ++p;

			/* Skip any leading whitespace after = */
			while (*p == ' ' || *p == '\t')
				lp = ++p;

			attr = sshbuf_dup_string(buf);
			sshbuf_reset(buf);
			break;
		case ',':
			if (attr == NULL) {
				sshbuf_free(buf);
				return (errf("SyntaxError", NULL, "Unexpected "
				    "COMMA in DN at '%s'", p));
			}
			/* Trim any trailing whitespace from the value */
			pp = p;
			while (*(pp - 1) == ' ' || *(pp - 1) == '\t')
				--pp;

			VERIFY0(sshbuf_put(buf, lp, (pp - lp)));
			lp = ++p;

			/* Skip any leading whitespace after = */
			while (*p == ' ' || *p == '\t')
				lp = ++p;

			val = sshbuf_dup_string(buf);
			sshbuf_reset(buf);

			err = add_dn_component(attr, val, name);
			if (err != ERRF_OK) {
				sshbuf_free(buf);
				return (err);
			}

			free(attr);
			free(val);
			attr = NULL;
			val = NULL;

			break;
		}
	}
	if (lp != p) {
		if (attr == NULL) {
			sshbuf_free(buf);
			return (errf("SyntaxError", NULL, "Reached end of "
			    "string, expected attribute value in DN '%s'",
			    dnstr));
		}
		/* Trim any trailing whitespace from the value */
		pp = p;
		while (*(pp - 1) == ' ' || *(pp - 1) == '\t')
			--pp;

		VERIFY0(sshbuf_put(buf, lp, (pp - lp)));
		lp = ++p;
		val = sshbuf_dup_string(buf);
		sshbuf_reset(buf);

		err = add_dn_component(attr, val, name);
		if (err != ERRF_OK)
			return (err);

		free(attr);
		free(val);
	}

	sshbuf_free(buf);
	return (ERRF_OK);
}

static void
varval_free(struct varval *vv)
{
	struct varval *next;
	for (; vv != NULL; vv = next) {
		next = vv->vv_next;
		if (vv->vv_type == VV_STRING)
			free(vv->vv_string);
		free(vv);
	}
}

static char *
varval_unparse(const struct varval *vv0)
{
	struct sshbuf *buf;
	const struct varval *vv;
	char *ret;

	buf = sshbuf_new();
	if (buf == NULL) {
		return (NULL);
	}

	for (vv = vv0; vv != NULL; vv = vv->vv_next) {
		if (vv->vv_type == VV_STRING) {
			VERIFY0(sshbuf_put(buf, vv->vv_string,
			    strlen(vv->vv_string)));
		} else if (vv->vv_type == VV_VAR) {
			VERIFY0(sshbuf_put_u8(buf, '%'));
			VERIFY0(sshbuf_put_u8(buf, '{'));
			VERIFY0(sshbuf_put(buf, vv->vv_var->cv_name,
			    strlen(vv->vv_var->cv_name)));
			VERIFY0(sshbuf_put_u8(buf, '}'));
		}
	}

	ret = sshbuf_dup_string(buf);
	sshbuf_free(buf);

	return (ret);
}

static struct varval *
varval_parse(const char *inp)
{
	const char *p, *lp;
	struct sshbuf *buf;
	struct varval *vv0, *vv, *vvn;

	vv0 = (vv = calloc(1, sizeof (struct varval)));
	if (vv == NULL)
		return (NULL);
	vv->vv_type = VV_STRING;
	buf = sshbuf_new();
	if (buf == NULL) {
		free(vv);
		return (NULL);
	}

	for (lp = (p = inp); *p != '\0'; ++p) {
		switch (*p) {
		case '\\':
			if (lp != p)
				VERIFY0(sshbuf_put(buf, lp, (p - lp)));
			switch (*(++p)) {
			case '\\':
				VERIFY0(sshbuf_put_u8(buf, *p));
				break;
			case 'n':
				VERIFY0(sshbuf_put_u8(buf, '\n'));
				break;
			}
			lp = p + 1;
			break;
		case '%':
			if (vv->vv_type != VV_STRING)
				continue;
			if (*(p + 1) != '{')
				continue;
			if (lp != p)
				VERIFY0(sshbuf_put(buf, lp, (p - lp)));
			++p;

			vv->vv_string = sshbuf_dup_string(buf);
			sshbuf_reset(buf);

			if (vv->vv_string == NULL) {
				vv->vv_type = VV_VAR;
				lp = ++p;
				break;
			}

			vvn = calloc(1, sizeof (struct varval));
			VERIFY(vvn != NULL);
			vvn->vv_type = VV_VAR;

			vv->vv_next = vvn;
			vv = vvn;

			lp = p + 1;
			break;
		case '}':
			if (vv->vv_type != VV_VAR)
				continue;
			if (lp != p)
				VERIFY0(sshbuf_put(buf, lp, (p - lp)));

			vv->vv_string = sshbuf_dup_string(buf);
			sshbuf_reset(buf);

			vvn = calloc(1, sizeof (struct varval));
			VERIFY(vvn != NULL);
			vvn->vv_type = VV_STRING;

			vv->vv_next = vvn;
			vv = vvn;

			lp = p + 1;
			break;
		}
	}
	if (lp != p)
		VERIFY0(sshbuf_put(buf, lp, (p - lp)));
	vv->vv_string = sshbuf_dup_string(buf);

	sshbuf_free(buf);

	return (vv0);
}

static struct cert_var *
find_var(struct cert_var *cv0, const char *name)
{
	struct cert_var *cv;

	for (cv = cv0; cv != NULL; cv = cv->cv_next) {
		if (strcmp(cv->cv_name, name) == 0) {
			return (cv);
		}
	}

	return (NULL);
}

static struct cert_var *
get_or_define_empty_var(struct cert_var_scope *rcs, const char *name,
    const char *help, uint flags)
{
	struct cert_var *rvar = NULL, *pvar = NULL;
	struct cert_var_scope *cs = rcs;

	for (cs = rcs; cs != NULL; cs = cs->cvs_parent) {
		struct cert_var *var;

		var = find_var(cs->cvs_vars, name);

		if (var == NULL) {
			var = calloc(1, sizeof(struct cert_var));
			VERIFY(var != NULL);
			var->cv_name = strdup(name);
			var->cv_scope = cs;
			VERIFY(var->cv_name != NULL);
			var->cv_next = cs->cvs_vars;
			cs->cvs_vars = var;
		}

		if (help != NULL) {
			free(var->cv_help);
			var->cv_help = strdup(help);
		}
		var->cv_flags |= flags;

		if (rvar == NULL)
			rvar = var;
		if (pvar != NULL)
			pvar->cv_parent = var;
		pvar = var;
	}

	return (rvar);
}

static errf_t *
cert_var_eval_into(struct cert_var *cv, struct sshbuf *buf)
{
	struct varval *vv;
	errf_t *err;

	while (cv->cv_value == NULL && cv->cv_parent != NULL)
		cv = cv->cv_parent;

	if (cv->cv_value == NULL) {
		return (errf("UndefinedCertVar", NULL, "Undefined certificate "
		    "variable '%s'", cv->cv_name));
	}

	for (vv = cv->cv_value; vv != NULL; vv = vv->vv_next) {
		if (vv->vv_type == VV_STRING && vv->vv_string != NULL) {
			VERIFY0(sshbuf_put(buf, vv->vv_string,
			    strlen(vv->vv_string)));
		} else if (vv->vv_type == VV_VAR) {
			err = cert_var_eval_into(vv->vv_var, buf);
			if (err != ERRF_OK) {
				err = errf("CertVarEvalError", err, "Failed to "
				    "evaluate certificate variable '%s'",
				    cv->cv_name);
				return (err);
			}
		}
	}

	return (ERRF_OK);
}


static errf_t *
populate_common(struct cert_var_scope *cs, X509 *cert, char *basic, char *ku,
    char *eku)
{
	errf_t *err;
	char *lifetime, *dnstr;
	char *p;
	unsigned long lifetime_secs;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	X509_NAME *subj;

	err = scope_eval(cs, "lifetime", &lifetime);
	if (err != ERRF_OK) {
		return (errf("MissingParameter", err, "certificate 'lifetime' "
		    "is required"));
	}
	errno = 0;
	lifetime_secs = strtoul(lifetime, &p, 10);
	if (errno != 0) {
		return (errf("SyntaxError", errfno("strtoul", errno,
		    NULL), "Error parsing contents of 'lifetime' "
		    "certificate variable: '%s'", lifetime));
	}
	if (*p == 'h' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600;
	} else if (*p == 'd' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600*24;
	} else if (*p == 'w' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600*24*7;
	} else if (*p == 'y' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600*24*365;
	}
	if (*p != '\0') {
		return (errf("SyntaxError", NULL, "Error parsing contents "
		    "of 'lifetime' certificate variable: trailing garbage '%s'",
		    p));
	}
	free(lifetime);

	VERIFY(X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL);
	VERIFY(X509_gmtime_adj(X509_get_notAfter(cert), lifetime_secs) != NULL);

	subj = X509_NAME_new();
	VERIFY(subj != NULL);

	err = scope_eval(cs, "dn", &dnstr);
	if (err != ERRF_OK) {
		return (errf("MissingParameter", err, "certificate 'dn' "
		    "is required"));
	}

	err = parse_dn(dnstr, subj);
	if (err != ERRF_OK) {
		return (errf("InvalidDN", err, "failed to parse certificate "
		    "'dn' value: '%s'", dnstr));
	}
	free(dnstr);

	VERIFY(X509_set_subject_name(cert, subj) == 1);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
	    (char *)basic);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage, (char *)ku);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	if (eku != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_ext_key_usage,
		    (char *)eku);
		VERIFY(ext != NULL);
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	return (ERRF_OK);
}

static errf_t *
add_common_princs(struct cert_var_scope *cs, STACK_OF(GENERAL_NAME) *gns)
{
	char *upn, *krbpn;
	errf_t *err;
	ASN1_STRING *xdata;
	GENERAL_NAME *gn;
	ASN1_OBJECT *obj;
	PKINIT_PRINC *princ;
	ASN1_TYPE *typ;

	err = scope_eval(cs, "ad_upn", &upn);
	if (err != ERRF_OK) {
		upn = NULL;
		errf_free(err);
	}

	err = scope_eval(cs, "krb5_principal", &krbpn);
	if (err != ERRF_OK) {
		krbpn = NULL;
		errf_free(err);
	}

	if (upn != NULL) {
		ASN1_UTF8STRING *str;

		obj = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.3", 1);
		VERIFY(obj != NULL);

		str = ASN1_UTF8STRING_new();
		VERIFY(str != NULL);
		VERIFY(ASN1_STRING_set(str, upn, strlen(upn)) == 1);

		typ = ASN1_TYPE_new();
		VERIFY(typ != NULL);
		ASN1_TYPE_set(typ, V_ASN1_UTF8STRING, str);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);
		VERIFY(GENERAL_NAME_set0_othername(gn, obj, typ) == 1);
		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	}

	if (krbpn != NULL) {
		obj = OBJ_txt2obj("1.3.6.1.5.2.2", 1);
		VERIFY(obj != NULL);

		princ = v2i_PKINIT_PRINC(NULL, krbpn);
		if (princ == NULL) {
			err = errf("SyntaxError", NULL, "failed to "
			    "parse krb5 principal name '%s'", krbpn);
			free(upn);
			free(krbpn);
			sk_GENERAL_NAME_pop_free(gns,
			    GENERAL_NAME_free);
			return (err);
		}

		xdata = pack_PKINIT_PRINC(princ, NULL);
		VERIFY(xdata != NULL);

		typ = ASN1_TYPE_new();
		VERIFY(typ != NULL);
		ASN1_TYPE_set(typ, V_ASN1_SEQUENCE, xdata);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);
		GENERAL_NAME_set0_othername(gn, obj, typ);
		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	}

	return (ERRF_OK);
}

static errf_t *
populate_common_princs(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	X509_EXTENSION *ext;
	STACK_OF(GENERAL_NAME) *gns;

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		return (err);
	}

	if (sk_GENERAL_NAME_num(gns) > 0) {
		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gns);
		VERIFY(ext != NULL);
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	return (ERRF_OK);
}

static errf_t *
populate_user_auth(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *upn, *krbpn;
	const char *eku = "clientAuth";

	err = scope_eval(cs, "ad_upn", &upn);
	if (err != ERRF_OK) {
		errf_free(err);
		upn = NULL;
	}
	err = scope_eval(cs, "krb5_principal", &krbpn);
	if (err != ERRF_OK) {
		errf_free(err);
		krbpn = NULL;
	}
	if (upn != NULL && krbpn != NULL) {
		eku = "clientAuth,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.4";
	} else if (upn != NULL) {
		eku = "clientAuth,1.3.6.1.4.1.311.20.2.2";
	} else if (krbpn != NULL) {
		eku = "clientAuth,1.3.6.1.5.2.3.4";
	}
	free(upn);
	free(krbpn);

	err = populate_common(cs, cert, "critical,CA:FALSE",
	    "critical,digitalSignature,nonRepudiation",
	    (char *)eku);
	if (err != ERRF_OK)
		return (err);

	err = populate_common_princs(cs, cert);
	if (err != ERRF_OK)
		return (err);

	return (ERRF_OK);
}

static errf_t *
populate_user_key_mgmt(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *upn;
	const char *eku = NULL;

	err = scope_eval(cs, "ad_upn", &upn);
	if (err == ERRF_OK) {
		eku = "1.3.6.1.4.1.311.10.3.4";
	} else {
		errf_free(err);
		upn = NULL;
	}

	err = populate_common(cs, cert, "critical,CA:FALSE",
	    "critical,keyAgreement,keyEncipherment,dataEncipherment",
	    (char *)eku);
	if (err != ERRF_OK)
		return (err);

	if (upn != NULL) {
		STACK_OF(GENERAL_NAME) *gns;
		GENERAL_NAME *gn;
		ASN1_OBJECT *obj;
		ASN1_TYPE *typ;
		ASN1_UTF8STRING *str;
		X509_EXTENSION *ext;

		gns = sk_GENERAL_NAME_new_null();
		VERIFY(gns != NULL);

		obj = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.3", 1);
		VERIFY(obj != NULL);

		str = ASN1_UTF8STRING_new();
		VERIFY(str != NULL);
		VERIFY(ASN1_STRING_set(str, upn, strlen(upn)) == 1);

		typ = ASN1_TYPE_new();
		VERIFY(typ != NULL);
		ASN1_TYPE_set(typ, V_ASN1_UTF8STRING, str);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);
		VERIFY(GENERAL_NAME_set0_othername(gn, obj, typ) == 1);
		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);

		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gns);
		VERIFY(ext != NULL);
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);

		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
	}
	free(upn);

	return (ERRF_OK);
}

static errf_t *
populate_user_email(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *email, *cfg;
	size_t cfglen;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;

	err = scope_eval(cs, "email", &email);
	if (err != ERRF_OK)
		return (err);

	err = populate_common(cs, cert, "critical,CA:FALSE",
	    "critical,digitalSignature,keyAgreement,keyEncipherment,"
	    "dataEncipherment,nonRepudiation",
	    "critical,emailProtection,"
	    "1.3.6.1.4.1.311.3.10.3.12,"	/* MS doc signing */
	    "1.2.840.113583.1.1.5"		/* Adobe doc signing */);
	if (err != ERRF_OK)
		return (err);

	cfglen = strlen(email) + 8;
	cfg = calloc(cfglen, 1);
	VERIFY(cfg != NULL);
	strlcat(cfg, "email:", cfglen);
	strlcat(cfg, email, cfglen);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_subject_alt_name, cfg);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	free(cfg);
	free(email);

	return (ERRF_OK);
}

static errf_t *
populate_code_signing(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *email;
	X509_EXTENSION *ext;
	STACK_OF(GENERAL_NAME) *gns;

	err = populate_common(cs, cert, "critical,CA:FALSE",
	    "critical,digitalSignature,nonRepudiation",
	    "critical,1.3.6.1.5.5.7.3.3");
	if (err != ERRF_OK)
		return (err);

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = scope_eval(cs, "email", &email);
	if (err != ERRF_OK) {
		errf_free(err);
		email = NULL;
	}
	if (email != NULL) {
		ASN1_IA5STRING *ia5;
		GENERAL_NAME *gn;

		ia5 = ASN1_IA5STRING_new();
		VERIFY(ia5 != NULL);
		VERIFY(ASN1_STRING_set(ia5, email, -1) == 1);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);

		GENERAL_NAME_set0_value(gn, GEN_EMAIL, ia5);

		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	}
	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		return (err);
	}

	if (sk_GENERAL_NAME_num(gns) > 0) {
		ext = X509V3_EXT_i2d(NID_subject_alt_name, 1, gns);
		VERIFY(ext != NULL);
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	return (ERRF_OK);
}

static errf_t *
populate_computer_auth(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *upn, *krbpn, *dns_name;
	const char *eku = "clientAuth,serverAuth";
	X509_EXTENSION *ext;
	GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) *gns;
	char *saveptr;
	char *tkn;

	err = scope_eval(cs, "dns_name", &dns_name);
	if (err != ERRF_OK)
		return (err);

	err = scope_eval(cs, "ad_upn", &upn);
	if (err != ERRF_OK) {
		errf_free(err);
		upn = NULL;
	}
	err = scope_eval(cs, "krb5_principal", &krbpn);
	if (err != ERRF_OK) {
		errf_free(err);
		krbpn = NULL;
	}
	if (upn != NULL && krbpn != NULL) {
		eku = "clientAuth,serverAuth,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.5";
	} else if (upn != NULL) {
		eku = "clientAuth,serverAuth,1.3.6.1.4.1.311.20.2.2";
	} else if (krbpn != NULL) {
		eku = "clientAuth,serverAuth,1.3.6.1.5.2.3.5";
	}
	free(upn);
	free(krbpn);

	err = populate_common(cs, cert, "critical,CA:FALSE",
	    "critical,digitalSignature,nonRepudiation",
	    (char *)eku);
	if (err != ERRF_OK)
		return (err);

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		return (err);
	}

	tkn = strtok_r(dns_name, "; ", &saveptr);
	if (tkn == NULL) {
		return (errf("SyntaxError", NULL, "Failed to parse dns_name: "
		    "%s", dns_name));
	}
	while (tkn != NULL) {
		ASN1_IA5STRING *ia5;

		ia5 = ASN1_IA5STRING_new();
		VERIFY(ia5 != NULL);
		VERIFY(ASN1_STRING_set(ia5, tkn, -1) == 1);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);

		GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);

		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);

		tkn = strtok_r(NULL, "; ", &saveptr);
	}

	ext = X509V3_EXT_i2d(NID_subject_alt_name, 1, gns);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	free(dns_name);

	return (ERRF_OK);
}

static errf_t *
populate_ca(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *namecons = NULL, *pathlen = NULL;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	char basic[128];
	char *eku = NULL;
	CONF *config = NULL;

	OPENSSL_load_builtin_modules();

	err = load_ossl_config("piv_ca", cs, &config);
	if (err != ERRF_OK)
		goto out;

	X509V3_set_nconf(&x509ctx, config);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	strlcpy(basic, "critical,CA:TRUE", sizeof (basic));
	err = scope_eval(cs, "path_len", &pathlen);
	if (err == ERRF_OK) {
		strlcat(basic, ",pathlen:", sizeof (basic));
		strlcat(basic, pathlen, sizeof (basic));
	} else {
		errf_free(err);
	}

	err = scope_eval(cs, "ext_key_usage", &eku);
	if (err != ERRF_OK) {
		errf_free(err);
		eku = NULL;
	}

	err = populate_common(cs, cert, basic,
	    "critical,digitalSignature,keyCertSign,cRLSign", eku);
	if (err != ERRF_OK)
		goto out;

	err = scope_eval(cs, "name_constraints", &namecons);
	if (err == ERRF_OK) {
		ext = X509V3_EXT_nconf_nid(config, &x509ctx,
		    NID_name_constraints, namecons);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_nconf_nid", "parsing "
			    "name constraint '%s'", namecons);
			goto out;
		}
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	} else {
		errf_free(err);
	}

	err = ERRF_OK;

out:
	free(namecons);
	free(pathlen);
	free(eku);
	NCONF_free(config);

	return (err);
}


static errf_t *
rpopulate_common(struct cert_var_scope *cs, X509_REQ *req,
    STACK_OF(X509_EXTENSION) *exts, char *basic, char *ku, char *eku)
{
	errf_t *err;
	char *dnstr;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	X509_NAME *subj;

	subj = X509_NAME_new();
	VERIFY(subj != NULL);

	err = scope_eval(cs, "dn", &dnstr);
	if (err != ERRF_OK) {
		return (errf("MissingParameter", err, "certificate 'dn' "
		    "is required"));
	}

	err = parse_dn(dnstr, subj);
	if (err != ERRF_OK) {
		return (errf("InvalidDN", err, "failed to parse certificate "
		    "'dn' value: '%s'", dnstr));
	}
	free(dnstr);

	VERIFY(X509_REQ_set_subject_name(req, subj) == 1);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, NULL, NULL, req, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
	    (char *)basic);
	VERIFY(ext != NULL);
	VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage, (char *)ku);
	VERIFY(ext != NULL);
	VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

	if (eku != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_ext_key_usage,
		    (char *)eku);
		VERIFY(ext != NULL);
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	}

	return (ERRF_OK);
}

static errf_t *
rpopulate_common_princs(struct cert_var_scope *cs, X509_REQ *req,
    STACK_OF(X509_EXTENSION) *exts)
{
	errf_t *err;
	X509_EXTENSION *ext;
	STACK_OF(GENERAL_NAME) *gns;

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		return (err);
	}

	if (sk_GENERAL_NAME_num(gns) > 0) {
		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gns);
		VERIFY(ext != NULL);
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	}

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	return (ERRF_OK);
}

static errf_t *
rpopulate_user_auth(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *upn = NULL, *krbpn = NULL;
	const char *eku = "clientAuth";
	STACK_OF(X509_EXTENSION) *exts;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = scope_eval(cs, "ad_upn", &upn);
	if (err != ERRF_OK) {
		errf_free(err);
		upn = NULL;
	}
	err = scope_eval(cs, "krb5_principal", &krbpn);
	if (err != ERRF_OK) {
		errf_free(err);
		krbpn = NULL;
	}
	if (upn != NULL && krbpn != NULL) {
		eku = "clientAuth,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.4";
	} else if (upn != NULL) {
		eku = "clientAuth,1.3.6.1.4.1.311.20.2.2";
	} else if (krbpn != NULL) {
		eku = "clientAuth,1.3.6.1.5.2.3.4";
	}
	free(upn);
	free(krbpn);

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE",
	    "critical,digitalSignature,nonRepudiation",
	    (char *)eku);
	if (err != ERRF_OK)
		return (err);

	err = rpopulate_common_princs(cs, req, exts);
	if (err != ERRF_OK)
		return (err);

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return (ERRF_OK);
}

static errf_t *
rpopulate_user_key_mgmt(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *upn;
	const char *eku = NULL;
	STACK_OF(X509_EXTENSION) *exts;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = scope_eval(cs, "ad_upn", &upn);
	if (err == ERRF_OK) {
		eku = "1.3.6.1.4.1.311.10.3.4";
	} else {
		errf_free(err);
		upn = NULL;
	}

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE",
	    "critical,keyAgreement,keyEncipherment,dataEncipherment",
	    (char *)eku);
	if (err != ERRF_OK)
		return (err);

	if (upn != NULL) {
		STACK_OF(GENERAL_NAME) *gns;
		GENERAL_NAME *gn;
		ASN1_OBJECT *obj;
		ASN1_TYPE *typ;
		ASN1_UTF8STRING *str;
		X509_EXTENSION *ext;

		gns = sk_GENERAL_NAME_new_null();
		VERIFY(gns != NULL);

		obj = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.3", 1);
		VERIFY(obj != NULL);

		str = ASN1_UTF8STRING_new();
		VERIFY(str != NULL);
		VERIFY(ASN1_STRING_set(str, upn, strlen(upn)) == 1);

		typ = ASN1_TYPE_new();
		VERIFY(typ != NULL);
		ASN1_TYPE_set(typ, V_ASN1_UTF8STRING, str);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);
		VERIFY(GENERAL_NAME_set0_othername(gn, obj, typ) == 1);
		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);

		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gns);
		VERIFY(ext != NULL);
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
	}
	free(upn);

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return (ERRF_OK);
}

static errf_t *
rpopulate_user_email(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *email, *cfg;
	size_t cfglen;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	STACK_OF(X509_EXTENSION) *exts;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = scope_eval(cs, "email", &email);
	if (err != ERRF_OK)
		return (err);

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE",
	    "critical,digitalSignature,keyAgreement,keyEncipherment,"
	    "dataEncipherment,nonRepudiation",
	    "critical,emailProtection,"
	    "1.3.6.1.4.1.311.3.10.3.12,"	/* MS doc signing */
	    "1.2.840.113583.1.1.5"		/* Adobe doc signing */);
	if (err != ERRF_OK)
		return (err);

	cfglen = strlen(email) + 8;
	cfg = calloc(cfglen, 1);
	VERIFY(cfg != NULL);
	strlcat(cfg, "email:", cfglen);
	strlcat(cfg, email, cfglen);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, NULL, NULL, req, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_subject_alt_name, cfg);
	VERIFY(ext != NULL);
	VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	free(cfg);
	free(email);

	return (ERRF_OK);
}

static errf_t *
rpopulate_computer_auth(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *upn, *krbpn, *dns_name;
	const char *eku = "clientAuth,serverAuth";
	X509_EXTENSION *ext;
	GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) *gns;
	char *saveptr;
	char *tkn;
	STACK_OF(X509_EXTENSION) *exts;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = scope_eval(cs, "dns_name", &dns_name);
	if (err != ERRF_OK)
		return (err);

	err = scope_eval(cs, "ad_upn", &upn);
	if (err != ERRF_OK) {
		errf_free(err);
		upn = NULL;
	}
	err = scope_eval(cs, "krb5_principal", &krbpn);
	if (err != ERRF_OK) {
		errf_free(err);
		krbpn = NULL;
	}
	if (upn != NULL && krbpn != NULL) {
		eku = "clientAuth,serverAuth,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.5";
	} else if (upn != NULL) {
		eku = "clientAuth,serverAuth,1.3.6.1.4.1.311.20.2.2";
	} else if (krbpn != NULL) {
		eku = "clientAuth,serverAuth,1.3.6.1.5.2.3.5";
	}
	free(upn);
	free(krbpn);

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE",
	    "critical,digitalSignature,nonRepudiation",
	    (char *)eku);
	if (err != ERRF_OK)
		return (err);

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		return (err);
	}

	tkn = strtok_r(dns_name, "; ", &saveptr);
	if (tkn == NULL) {
		return (errf("SyntaxError", NULL, "Failed to parse dns_name: "
		    "%s", dns_name));
	}
	while (tkn != NULL) {
		ASN1_IA5STRING *ia5;

		ia5 = ASN1_IA5STRING_new();
		VERIFY(ia5 != NULL);
		VERIFY(ASN1_STRING_set(ia5, tkn, -1) == 1);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);

		GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);

		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);

		tkn = strtok_r(NULL, "; ", &saveptr);
	}
	free(dns_name);

	ext = X509V3_EXT_i2d(NID_subject_alt_name, 1, gns);
	VERIFY(ext != NULL);
	VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return (ERRF_OK);
}

static errf_t *
rpopulate_code_signing(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *email;
	X509_EXTENSION *ext;
	STACK_OF(GENERAL_NAME) *gns;
	STACK_OF(X509_EXTENSION) *exts;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE",
	    "critical,digitalSignature,nonRepudiation",
	    "critical,1.3.6.1.5.5.7.3.3");
	if (err != ERRF_OK)
		return (err);

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = scope_eval(cs, "email", &email);
	if (err != ERRF_OK) {
		errf_free(err);
		email = NULL;
	}
	if (email != NULL) {
		ASN1_IA5STRING *ia5;
		GENERAL_NAME *gn;

		ia5 = ASN1_IA5STRING_new();
		VERIFY(ia5 != NULL);
		VERIFY(ASN1_STRING_set(ia5, email, -1) == 1);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);

		GENERAL_NAME_set0_value(gn, GEN_EMAIL, ia5);

		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	}
	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		return (err);
	}

	if (sk_GENERAL_NAME_num(gns) > 0) {
		ext = X509V3_EXT_i2d(NID_subject_alt_name, 1, gns);
		VERIFY(ext != NULL);
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	}

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return (ERRF_OK);
}

static errf_t *
rpopulate_ca(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *namecons = NULL, *pathlen = NULL;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	STACK_OF(X509_EXTENSION) *exts;
	char basic[128];
	char *eku = NULL;
	CONF *config = NULL;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	OPENSSL_load_builtin_modules();

	err = load_ossl_config("piv_ca", cs, &config);
	if (err != ERRF_OK)
		goto out;

	X509V3_set_nconf(&x509ctx, config);
	X509V3_set_ctx(&x509ctx, NULL, NULL, req, NULL, 0);

	strlcpy(basic, "critical,CA:TRUE", sizeof (basic));
	err = scope_eval(cs, "path_len", &pathlen);
	if (err == ERRF_OK) {
		strlcat(basic, ",pathlen:", sizeof (basic));
		strlcat(basic, pathlen, sizeof (basic));
	} else {
		errf_free(err);
	}

	err = scope_eval(cs, "ext_key_usage", &eku);
	if (err != ERRF_OK) {
		errf_free(err);
		eku = NULL;
	}

	err = rpopulate_common(cs, req, exts, basic,
	    "critical,digitalSignature,keyCertSign,cRLSign", eku);
	if (err != ERRF_OK)
		goto out;

	err = scope_eval(cs, "name_constraints", &namecons);
	if (err == ERRF_OK) {
		ext = X509V3_EXT_nconf_nid(config, &x509ctx,
		    NID_name_constraints, namecons);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_nconf_nid", "parsing "
			    "name constraint '%s'", namecons);
			goto out;
		}
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	} else {
		errf_free(err);
	}

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	err = ERRF_OK;

out:
	free(namecons);
	free(pathlen);
	free(eku);
	NCONF_free(config);

	return (err);
}

static errf_t *
set_pkey_from_sshkey(struct sshkey *pubkey, struct piv_token *tkn,
    EVP_PKEY **pkey, enum sshdigest_types *wantalg, int *nid)
{
	int rc;
	errf_t *err = ERRF_OK;
	RSA *copy = NULL;
	BIGNUM *e = NULL, *n = NULL;
	EC_KEY *ecopy = NULL;
	uint i;

	*pkey = EVP_PKEY_new();
	VERIFY(*pkey != NULL);

	if (pubkey->type == KEY_RSA) {
		copy = RSA_new();
		if (copy == NULL) {
			make_sslerrf(err, "RSA_new", "copying pubkey");
			goto out;
		}

		e = BN_dup(RSA_get0_e(pubkey->rsa));
		n = BN_dup(RSA_get0_n(pubkey->rsa));
		if (e == NULL || n == NULL) {
			make_sslerrf(err, "BN_dup", "copying pubkey");
			goto out;
		}

		rc = RSA_set0_key(copy, n, e, NULL);
		if (rc != 1) {
			make_sslerrf(err, "RSA_set0_key", "copying pubkey");
			goto out;
		}
		/* copy now owns these */
		n = NULL;
		e = NULL;

		rc = EVP_PKEY_assign_RSA(*pkey, copy);
		if (rc != 1) {
			make_sslerrf(err, "EVP_PKEY_assign_RSA",
			    "copying pubkey");
			goto out;
		}
		/* pkey owns this now */
		copy = NULL;

		*nid = NID_sha256WithRSAEncryption;
		*wantalg = SSH_DIGEST_SHA256;

	} else if (pubkey->type == KEY_ECDSA) {
		boolean_t haveSha256 = B_FALSE;
		boolean_t haveSha1 = B_FALSE;

		ecopy = EC_KEY_dup(pubkey->ecdsa);
		if (ecopy == NULL) {
			make_sslerrf(err, "EC_KEY_dup", "copying pubkey");
			goto out;
		}

		rc = EVP_PKEY_assign_EC_KEY(*pkey, ecopy);
		if (rc != 1) {
			make_sslerrf(err, "EVP_PKEY_assign_EC_KEY",
			    "copying pubkey");
			goto out;
		}
		/* pkey owns this now */
		ecopy = NULL;

		if (tkn != NULL) {
			for (i = 0; i < piv_token_nalgs(tkn); ++i) {
				enum piv_alg alg = piv_token_alg(tkn, i);
				if (alg == PIV_ALG_ECCP256_SHA256) {
					haveSha256 = B_TRUE;
				} else if (alg == PIV_ALG_ECCP256_SHA1) {
					haveSha1 = B_TRUE;
				}
			}
		}
		if (haveSha1 && !haveSha256) {
			*nid = NID_ecdsa_with_SHA1;
			*wantalg = SSH_DIGEST_SHA1;
		} else {
			*nid = NID_ecdsa_with_SHA256;
			*wantalg = SSH_DIGEST_SHA256;
		}

	} else {
		err = errf("InvalidKeyType", NULL, "invalid key type: %d",
		    pubkey->type);
		goto out;
	}

out:
	RSA_free(copy);
	EC_KEY_free(ecopy);
	BN_free(e);
	BN_free(n);

	return (err);
}

static errf_t *
pkey_key_id(EVP_PKEY *pkey, ASN1_OCTET_STRING **out)
{
	errf_t *err;
	int rc;
	ASN1_OCTET_STRING *kid = NULL;
	X509_PUBKEY *xpub = NULL;
	const uint8_t *pkdata;
	uint8_t *pkhash = NULL;
	uint pkhlen;
	int pklen;

	rc = X509_PUBKEY_set(&xpub, pkey);
	if (rc != 1) {
		make_sslerrf(err, "X509_PUBKEY_set", "allocating keyid");
		goto out;
	}

	rc = X509_PUBKEY_get0_param(NULL, &pkdata, &pklen, NULL, xpub);
	VERIFY(rc == 1);

	pkhlen = SHA_DIGEST_LENGTH;
	pkhash = malloc(pkhlen);
	VERIFY(pkhash != NULL);
	rc = EVP_Digest(pkdata, pklen, pkhash, &pkhlen, EVP_sha1(), NULL);
	if (rc != 1) {
		make_sslerrf(err, "EVP_Digest", "allocating keyid");
		goto out;
	}

	kid = ASN1_OCTET_STRING_new();
	if (kid == NULL) {
		make_sslerrf(err, "ASN1_OCTET_STRING_new", "allocating keyid");
		goto out;
	}
	ASN1_STRING_set(kid, pkhash, pkhlen);

	*out = kid;
	kid = NULL;
	err = ERRF_OK;

out:
	free(pkhash);
	X509_PUBKEY_free(xpub);
	ASN1_OCTET_STRING_free(kid);
	return (err);
}

errf_t *
piv_selfsign_cert(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509 *cert)
{
	errf_t *err;
	EVP_PKEY *pkey;
	int rc;
	enum sshdigest_types wantalg;
	int nid;
	ASN1_OCTET_STRING *kid = NULL;

	if (pubkey == NULL)
		pubkey = piv_slot_pubkey(slot);
	if (pubkey == NULL) {
		return (errf("ArgumentError", NULL, "No pubkey given to "
		    "piv_sign_cert"));
	}

	err = set_pkey_from_sshkey(pubkey, tkn, &pkey, &wantalg, &nid);
	if (err != ERRF_OK)
		return (err);

	rc = X509_set_pubkey(cert, pkey);
	if (rc != 1) {
		make_sslerrf(err, "X509_set_pubkey", "setting new pubkey");
		goto out;
	}

	err = pkey_key_id(pkey, &kid);
	if (err != ERRF_OK)
		goto out;

	rc = X509_add1_ext_i2d(cert, NID_subject_key_identifier, kid, 0,
	    X509V3_ADD_REPLACE);
	if (rc != 1) {
		make_sslerrf(err, "X509_add1_ext_i2d", "adding subject "
		    "key id");
		goto out;
	}

	err = piv_sign_cert(tkn, slot, pubkey, cert);

out:
	ASN1_OCTET_STRING_free(kid);
	EVP_PKEY_free(pkey);
	return (err);
}

static errf_t *
agent_sign_cert(int fd, struct sshkey *pubkey, X509 *cert)
{
	errf_t *err;
	int rc;
	enum sshdigest_types wantalg, hashalg;
	int nid;
	EVP_PKEY *pkey;
	ASN1_BIT_STRING *asnsig = NULL;
	X509_ALGOR *algor = NULL;
	ASN1_OBJECT *algobj;
	uint8_t *tbs = NULL, *sig = NULL;
	size_t tbslen, siglen;
	AUTHORITY_KEYID *akid = NULL;
	ASN1_OCTET_STRING *kid = NULL;
	const char *alg = NULL;
	struct sshbuf *sshsig = NULL, *asn1sig = NULL;

	VERIFY(pubkey != NULL);

	if (pubkey->type == KEY_RSA)
		alg = "rsa-sha2-256";

	err = set_pkey_from_sshkey(pubkey, NULL, &pkey, &wantalg, &nid);
	if (err != ERRF_OK)
		return (err);

	err = pkey_key_id(pkey, &kid);
	if (err != ERRF_OK)
		goto out;

	akid = AUTHORITY_KEYID_new();
	if (akid == NULL) {
		make_sslerrf(err, "AUTHORITY_KEYID_new", "allocating keyid");
		goto out;
	}
	akid->keyid = kid;
	kid = NULL;

	rc = X509_add1_ext_i2d(cert, NID_authority_key_identifier, akid, 0,
	    X509V3_ADD_REPLACE);
	if (rc != 1) {
		make_sslerrf(err, "X509_add1_ext_i2d", "adding authority "
		    "key id");
		goto out;
	}

	algobj = OBJ_nid2obj(nid);
	if (algobj == NULL) {
		make_sslerrf(err, "OBJ_nid2obj", "setting signing algo");
		goto out;
	}

	X509_get0_signature((const ASN1_BIT_STRING **)&asnsig,
	    (const X509_ALGOR **)&algor, cert);

	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	algor = (X509_ALGOR *)X509_get0_tbs_sigalg(cert);
	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	tbslen = i2d_re_X509_tbs(cert, &tbs);
	if (tbslen == 0) {
		make_sslerrf(err, "i2d_re_X509_tbs",
		    "encoding to-be-signed cert req");
		goto out;
	}

	rc = ssh_agent_sign(fd, pubkey, &sig, &siglen, tbs, tbslen, alg, 0);
	if (rc != 0) {
		err = ssherrf("ssh_agent_sign", rc);
		goto out;
	}

	sshsig = sshbuf_from(sig, siglen);
	VERIFY(sshsig != NULL);

	asn1sig = sshbuf_new();
	VERIFY(asn1sig != NULL);

	rc = sshkey_sig_to_asn1(pubkey, sshsig, &hashalg, asn1sig);
	if (rc != 0) {
		err = ssherrf("sshkey_sig_to_asn1", rc);
		goto out;
	}

	if (hashalg != wantalg) {
		err = errf("SignAlgoMismatch", NULL, "Agent could not sign "
		    "with the requested hash algorithm");
		goto out;
	}

	ASN1_STRING_set(asnsig, sshbuf_ptr(asn1sig), sshbuf_len(asn1sig));
	asnsig->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	err = ERRF_OK;

out:
	sshbuf_free(asn1sig);
	sshbuf_free(sshsig);
	ASN1_OCTET_STRING_free(kid);
	AUTHORITY_KEYID_free(akid);
	EVP_PKEY_free(pkey);
	OPENSSL_free(tbs);
	return (err);
}

errf_t *
piv_sign_cert(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509 *cert)
{
	errf_t *err;
	int rc;
	enum sshdigest_types wantalg, hashalg;
	int nid;
	EVP_PKEY *pkey;
	ASN1_BIT_STRING *asnsig = NULL;
	X509_ALGOR *algor = NULL;
	ASN1_OBJECT *algobj;
	uint8_t *tbs = NULL, *sig = NULL;
	size_t tbslen, siglen;
	AUTHORITY_KEYID *akid = NULL;
	ASN1_OCTET_STRING *kid = NULL;

	if (pubkey == NULL)
		pubkey = piv_slot_pubkey(slot);
	if (pubkey == NULL) {
		return (errf("ArgumentError", NULL, "No pubkey given to "
		    "piv_sign_cert"));
	}

	err = set_pkey_from_sshkey(pubkey, tkn, &pkey, &wantalg, &nid);
	if (err != ERRF_OK)
		return (err);

	err = pkey_key_id(pkey, &kid);
	if (err != ERRF_OK)
		goto out;

	akid = AUTHORITY_KEYID_new();
	if (akid == NULL) {
		make_sslerrf(err, "AUTHORITY_KEYID_new", "allocating keyid");
		goto out;
	}
	akid->keyid = kid;
	kid = NULL;

	rc = X509_add1_ext_i2d(cert, NID_authority_key_identifier, akid, 0,
	    X509V3_ADD_REPLACE);
	if (rc != 1) {
		make_sslerrf(err, "X509_add1_ext_i2d", "adding authority "
		    "key id");
		goto out;
	}

	algobj = OBJ_nid2obj(nid);
	if (algobj == NULL) {
		make_sslerrf(err, "OBJ_nid2obj", "setting signing algo");
		goto out;
	}

	X509_get0_signature((const ASN1_BIT_STRING **)&asnsig,
	    (const X509_ALGOR **)&algor, cert);

	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	algor = (X509_ALGOR *)X509_get0_tbs_sigalg(cert);
	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	tbslen = i2d_re_X509_tbs(cert, &tbs);
	if (tbslen == 0) {
		make_sslerrf(err, "i2d_re_X509_tbs",
		    "encoding to-be-signed cert req");
		goto out;
	}

	hashalg = wantalg;

	err = piv_sign(tkn, slot, tbs, tbslen, &hashalg, &sig, &siglen);
	if (err != ERRF_OK)
		goto out;

	if (hashalg != wantalg) {
		err = errf("SignAlgoMismatch", NULL, "Card could not sign "
		    "with the requested hash algorithm");
		goto out;
	}

	ASN1_STRING_set(asnsig, sig, siglen);
	asnsig->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	err = ERRF_OK;

out:
	ASN1_OCTET_STRING_free(kid);
	AUTHORITY_KEYID_free(akid);
	EVP_PKEY_free(pkey);
	OPENSSL_free(tbs);
	return (err);
}

errf_t *
piv_sign_cert_req(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509_REQ *req)
{
	errf_t *err;
	EVP_PKEY *pkey = NULL;
	enum sshdigest_types wantalg, hashalg;
	int nid;
	int rc;
	ASN1_BIT_STRING *asnsig = NULL;
	X509_ALGOR *algor = NULL;
	ASN1_OBJECT *algobj;
	uint8_t *tbs = NULL, *sig = NULL;
	size_t tbslen, siglen;

	if (pubkey == NULL)
		pubkey = piv_slot_pubkey(slot);
	if (pubkey == NULL) {
		return (errf("ArgumentError", NULL, "No pubkey given to "
		    "piv_sign_cert"));
	}

	err = set_pkey_from_sshkey(pubkey, tkn, &pkey, &wantalg, &nid);
	if (err != ERRF_OK)
		return (err);

	rc = X509_REQ_set_pubkey(req, pkey);
	if (rc != 1) {
		make_sslerrf(err, "X509_REQ_set_pubkey", "setting new pubkey");
		goto out;
	}

	algobj = OBJ_nid2obj(nid);
	if (algobj == NULL) {
		make_sslerrf(err, "OBJ_nid2obj", "setting signing algo");
		goto out;
	}

	X509_REQ_get0_signature(req, (const ASN1_BIT_STRING **)&asnsig,
	    (const X509_ALGOR **)&algor);

	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	tbslen = i2d_re_X509_REQ_tbs(req, &tbs);
	if (tbslen == 0) {
		make_sslerrf(err, "i2d_re_X509_REQ_tbs",
		    "encoding to-be-signed cert req");
		goto out;
	}

	hashalg = wantalg;

	err = piv_sign(tkn, slot, tbs, tbslen, &hashalg, &sig, &siglen);
	if (err != ERRF_OK)
		goto out;

	if (hashalg != wantalg) {
		err = errf("SignAlgoMismatch", NULL, "Card could not sign "
		    "with the requested hash algorithm");
		goto out;
	}

	ASN1_STRING_set(asnsig, sig, siglen);
	asnsig->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	err = ERRF_OK;

out:
	EVP_PKEY_free(pkey);
	OPENSSL_free(tbs);
	freezero(sig, siglen);
	return (err);
}

static errf_t *
load_ossl_config(const char *section, struct cert_var_scope *cs, CONF **out)
{
	errf_t *err;
	int rc;
	char *buf = NULL;
	char namebuf[PATH_MAX];
	char prefix[512];
	char *confstr = NULL;
	struct cert_var *cv, *cvv;
	BIO *bio = NULL;
	CONF *conf = NULL;
	char *fname = NULL;
	uint loaded = 0;
	struct cert_var_scope *cvs;

	conf = NCONF_new(NULL);
	if (conf == NULL) {
		make_sslerrf(err, "NCONF_new", "allocating config");
		goto out;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		make_sslerrf(err, "BIO_new", "allocating memory BIO");
		goto out;
	}

	for (cvs = cs; cvs != NULL; cvs = scope_parent(cvs)) {
		for (cv = scope_all_vars(cvs); cv != NULL;
		    cv = cert_var_next(cv)) {
			const char *name = cert_var_name(cv);

			if (strcmp(name, "openssl_config_file") == 0) {
				err = cert_var_eval(cv, &fname);
				if (err != ERRF_OK)
					continue;

				err = read_text_file(fname, &buf, NULL);
				if (err != ERRF_OK) {
					err = errf("OpenSSLConfigFileError",
					    err, "failed to read openssl.cnf");
					goto out;
				}

				strlcpy(namebuf, "_ossl_config:",
				    sizeof (namebuf));
				strlcat(namebuf, fname, sizeof (namebuf));
				name = namebuf;

				cvv = scope_lookup(cs, namebuf, 1);
				VERIFY(cvv != NULL);

				err = cert_var_set(cvv, buf);
				if (err != ERRF_OK)
					goto out;

				prefix[0] = '\0';

			} else if (name[0] == '@') {
				cvv = cv;
				strlcpy(prefix, "[", sizeof (prefix));
				strlcat(prefix, name + 1, sizeof (prefix));
				strlcat(prefix, "]\n", sizeof (prefix));

			} else {
				continue;
			}

			err = cert_var_eval(cvv, &confstr);
			if (err != ERRF_OK)
				goto out;

			BIO_puts(bio, prefix);
			BIO_puts(bio, confstr);
			BIO_puts(bio, "\n");

			++loaded;

			free(confstr);
			confstr = NULL;
			free(buf);
			buf = NULL;
			free(fname);
			fname = NULL;
		}
	}

	if (loaded > 0) {
		rc = NCONF_load_bio(conf, bio, NULL);
		if (rc != 1) {
			make_sslerrf(err, "NCONF_load_bio",
			    "loading openssl config");
			goto out;
		}

		rc = CONF_modules_load(conf, section,
		    CONF_MFLAGS_DEFAULT_SECTION);
		if (rc != 1) {
			make_sslerrf(err, "CONF_modules_load",
			    "loading config file '%s'", fname);
			goto out;
		}
	}

	*out = conf;
	conf = NULL;
	err = ERRF_OK;

out:
	free(fname);
	BIO_free(bio);
	free(confstr);
	NCONF_free(conf);
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
agent_sign_json(int fd, struct sshkey *pubkey, json_object *obj)
{
	int rc;
	errf_t *err;
	json_object *sigprop = NULL;
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

	json_object_object_del(obj, "signature");
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

	sigprop = json_object_new_string(sigb64);
	if (sigprop == NULL) {
		err = jsonerrf("json_object_new_string");
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
    json_object *obj)
{
	int rc;
	errf_t *err;
	json_object *sigprop = NULL;
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

	json_object_object_del(obj, "signature");
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

	sigprop = json_object_new_string(sigb64);
	if (sigprop == NULL) {
		err = jsonerrf("json_object_new_string");
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
verify_json(struct sshkey *pubkey, json_object *obj)
{
	int rc;
	const char *tmp;
	json_object *sigprop = NULL;
	errf_t *err;
	struct sshbuf *sigbuf = NULL, *tbsbuf = NULL;

	sigprop = json_object_object_get(obj, "signature");
	if (sigprop == NULL) {
		err = errf("JSONSignatureError", NULL, "No 'signature' "
		    "property found in JSON object");
		goto out;
	}
	json_object_get(sigprop);

	tmp = json_object_get_string(sigprop);
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

void
ca_close(struct ca *ca)
{
	struct ca_uri *uri, *nuri;
	struct ca_cert_tpl *ctpl, *nctpl;
	struct ca_token_tpl *ttpl, *nttpl;

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
	ebox_tpl_free(ca->ca_pin_tpl);
	ebox_tpl_free(ca->ca_backup_tpl);
	ebox_tpl_free(ca->ca_puk_tpl);
	ebox_tpl_free(ca->ca_admin_tpl);
	ebox_tpl_free(ca->ca_seqbase_tpl);
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

static errf_t *
parse_ebox_template(struct ca *ca, const char *name, json_object *obj)
{
	const char *b64;
	struct ebox_tpl *tpl;
	struct sshbuf *buf;
	int rc;
	errf_t *err;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	b64 = json_object_get_string(obj);
	rc = sshbuf_b64tod(buf, b64);
	if (rc != 0) {
		err = ssherrf("sshbuf_b64tod", rc);
		err = errf("ParseError", err, "Failed to parse ebox "
		    "template '%s'", name);
		sshbuf_free(buf);
		return (err);
	}
	err = sshbuf_get_ebox_tpl(buf, &tpl);
	if (err != ERRF_OK) {
		err = errf("ParseError", err, "Failed to parse ebox "
		    "template '%s'", name);
		sshbuf_free(buf);
		return (err);
	}
	sshbuf_free(buf);

	if (strcmp(name, "pin") == 0)
		ca->ca_pin_tpl = tpl;
	else if (strcmp(name, "backup") == 0)
		ca->ca_backup_tpl = tpl;
	else if (strcmp(name, "puk") == 0)
		ca->ca_puk_tpl = tpl;
	else if (strcmp(name, "admin") == 0)
		ca->ca_admin_tpl = tpl;
	else if (strcmp(name, "seqbase") == 0)
		ca->ca_seqbase_tpl = tpl;
	else {
		ebox_tpl_free(tpl);
		return (errf("InvalidProperty", NULL, "Unknown ebox "
		    "template '%s'", name));
	}

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
validate_cstring(const char *buf, size_t len, size_t maxlen)
{
	size_t i;
	for (i = 0; i < len; ++i) {
		if (buf[i] == '\0') {
			return (errf("StringValidationError", NULL,
			    "Expected string of %zu length, got %zu",
			    len, i));
		}
	}
	for (; i < maxlen; ++i) {
		if (buf[i] != '\0') {
			return (errf("StringValidationError", NULL,
			    "Garbage found after string value, expected "
			    "NUL padding"));
		}
	}
	return (ERRF_OK);
}

static errf_t *
read_text_file(const char *fname, char **out, size_t *outlen)
{
	FILE *f = NULL;
	struct stat st;
	char *buf = NULL;
	size_t buflen;
	size_t done;
	int rc;
	errf_t *err;

	f = fopen(fname, "r");
	if (f == NULL) {
		err = errfno("fopen", errno, "opening '%s'", fname);
		goto out;
	}

	bzero(&st, sizeof (st));
	rc = fstat(fileno(f), &st);
	if (rc != 0) {
		err = errfno("stat", errno, "stat'ing '%s'", fname);
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
		err = errf("EmptyFileError", NULL, "file '%s' is empty",
		    fname);
		goto out;
	}

	buflen = st.st_size + 1;
	if (buflen < st.st_size) {
		err = errf("OverflowError", NULL, "file size overflow");
		goto out;
	}
	if (buflen > 2*1024*1024) {
		err = errf("FileTooLarge", NULL, "file '%s' is too large: "
		    "size = %zu bytes", fname, st.st_size);
		goto out;
	}

	buf = malloc(buflen);
	if (buf == NULL) {
		err = errfno("malloc", errno, NULL);
		goto out;
	}

	done = fread(buf, 1, st.st_size, f);
	if (done < 0) {
		err = errfno("fread", errno, NULL);
		goto out;
	}
	if (done < st.st_size) {
		err = errf("ShortRead", NULL, "expected to read %zu bytes, "
		    "but only read %zu", st.st_size, done);
		goto out;
	}
	buf[st.st_size] = '\0';
	err = validate_cstring(buf, done, buflen);
	if (err != ERRF_OK) {
		err = errf("InvalidFileContent", err, "Invalid content in "
		    "text file '%s'", fname);
		goto out;
	}

	*out = buf;
	buf = NULL;
	if (outlen != NULL)
		*outlen = st.st_size;
	err = ERRF_OK;

out:
	if (f != NULL)
		fclose(f);
	free(buf);
	return (err);
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

	err = verify_json(ca->ca_pubkey, robj);
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
