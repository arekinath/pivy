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
#include <inttypes.h>

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
#include "openssh/authfd.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"
#include "pkinit_asn1.h"
#include "piv-ca.h"

#include "piv-internal.h"

enum req_flags {
	RQF_CERT                = (1<<0),
	RQF_CERT_REQ            = (1<<1)
};

struct param {
	const char      *cp_name;
	uint             cp_flags;
	const char      *cp_help;
};

struct cert_tpl {
	const char      *ct_name;
	const char      *ct_help;
	struct param     ct_params[16];
	errf_t          *(*ct_populate)(struct cert_var_scope *, X509 *);
	errf_t          *(*ct_populate_req)(struct cert_var_scope *, X509_REQ *);
};

static struct cert_var *get_or_define_empty_var(struct cert_var_scope *,
    const char *, const char *, uint);
static errf_t *cert_var_eval_into(struct cert_var *, struct sshbuf *);
static struct cert_var *add_undefined_deps(struct cert_var *, struct cert_var *);
static struct cert_var *cert_var_clone(struct cert_var *);
static struct cert_var *find_var(struct cert_var *, const char *);

static errf_t *load_ossl_config(const char *section,
    struct cert_var_scope *cs, CONF **out);

errf_t *read_text_file(const char *path, char **out, size_t *outlen);
errf_t *validate_cstring(const char *buf, size_t len, size_t maxlen);

#define PARAM_DN        { "dn", RQF_CERT | RQF_CERT_REQ, \
    "Distinguished name (e.g. 'cn=foo, o=company, c=AU')" }
#define PARAM_LIFETIME  { "lifetime", RQF_CERT, \
    "Certificate lifetime in seconds (or use unit suffixes 'h', 'd', 'w', 'y')" }
#define PARAM_AD_UPN    { "ad_upn", 0, \
    "Active Directory UPN (e.g. 'foobar@domain.com')" }
#define PARAM_KRB5_PN   { "krb5_principal", 0, \
    "Kerberos V principal name (e.g. 'user/admin@REALM')" }
#define	PARAM_AD_SID	{ "ad_sid", 0, "MS AD SID (see KB5014754). Accepts " \
    "string format (S-1-5-...) or base64-encoded " \
    "(AQUAAAA...) SIDs." }
#define PARAM_POLICIES	{ "cert_policies", 0, \
    "Certificate policies to apply (as an OpenSSL config expression)" }

static errf_t *populate_user_auth(struct cert_var_scope *, X509 *);
static errf_t *populate_user_key_mgmt(struct cert_var_scope *, X509 *);
static errf_t *populate_user_email(struct cert_var_scope *, X509 *);
static errf_t *populate_computer_auth(struct cert_var_scope *, X509 *);
static errf_t *populate_code_signing(struct cert_var_scope *, X509 *);
static errf_t *populate_ca(struct cert_var_scope *, X509 *);
static errf_t *populate_dn_only(struct cert_var_scope *, X509 *);

static errf_t *rpopulate_user_auth(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_user_key_mgmt(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_user_email(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_computer_auth(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_code_signing(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_ca(struct cert_var_scope *, X509_REQ *);
static errf_t *rpopulate_dn_only(struct cert_var_scope *, X509_REQ *);

struct cert_tpl cert_templates[] = {
	{
		.ct_name = "user-auth",
		.ct_help = "User auth certificate",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			PARAM_POLICIES,
			PARAM_AD_UPN,
			PARAM_KRB5_PN,
			PARAM_AD_SID,
			{ "is_ad_user", 0, "Set to 'yes' or 'true' to force "
			    "including the AD Smartcard Logon EKU without "
			    "ad_upn" },
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
			PARAM_POLICIES,
			PARAM_AD_UPN,
			PARAM_AD_SID,
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
			PARAM_POLICIES,
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
			PARAM_POLICIES,
			{ "dns_name", RQF_CERT | RQF_CERT_REQ, "DNS domain name" },
			PARAM_AD_UPN,
			PARAM_KRB5_PN,
			{ "is_ad_dc", 0, "Generate a KDC cert for an AD DC if 'yes'" },
			{ "ad_repl_guid", 0, "Hex GUID for AD email replication cert" },
			PARAM_AD_SID,
			{ "is_ike_server", 0, "Add IKE EKU for VPN servers if 'yes'" },
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
			PARAM_POLICIES,
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
			PARAM_POLICIES,
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
		.ct_name = "dn-only",
		.ct_help = "Sets DN, expiry and no extensions or other fields",
		.ct_params = {
			PARAM_DN,
			PARAM_LIFETIME,
			{ NULL }
		},
		.ct_populate = populate_dn_only,
		.ct_populate_req = rpopulate_dn_only
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
cert_tpl_first(void)
{
	return (&cert_templates[0]);
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

char *
cert_var_value(const struct cert_var *cv)
{
	while (cv->cv_value == NULL && cv->cv_parent != NULL)
		cv = cv->cv_parent;
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

void *
cert_var_alloc_private(struct cert_var *cv, size_t sz)
{
	VERIFY(cv->cv_priv == NULL);
	cv->cv_priv = calloc(1, sz);
	return (cv->cv_priv);
}

void *
cert_var_private(struct cert_var *cv)
{
	return (cv->cv_priv);
}

void
cert_var_free_private(struct cert_var *cv)
{
	free(cv->cv_priv);
	cv->cv_priv = NULL;
}

static void
cert_var_free(struct cert_var *cv)
{
	VERIFY(cv->cv_priv == NULL);
	free(cv->cv_name);
	free(cv->cv_help);
	varval_free(cv->cv_value);
	free(cv);
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
	struct cert_var *cv, *cv0 = NULL, *cvlast = NULL;
	const struct param *p;
	for (p = &tpl->ct_params[0]; p->cp_name != NULL; ++p) {
		cv = calloc(1, sizeof(struct cert_var));
		cv->cv_name = strdup(p->cp_name);
		if (p->cp_help != NULL)
			cv->cv_help = strdup(p->cp_help);
		cv->cv_flags = p->cp_flags;
		if (cvlast != NULL)
			cvlast->cv_next = cv;
		cvlast = cv;
		if (cv0 == NULL)
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

	VERIFY(cvs != NULL);
	VERIFY(name != NULL);
	VERIFY(undef == 1 || undef == 0);

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
	VERIFY(cv != NULL);
	VERIFY(cv->cv_scope != NULL);
	free(cv->cv_help);
	cv->cv_help = strdup(help);
}

errf_t *
cert_var_set(struct cert_var *var, const char *value)
{
	struct varval *vv;
	struct cert_var *cv;

	VERIFY(var != NULL);
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
			free(vv->vv_string);
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

	VERIFY(cvs != NULL);

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
			free(vv->vv_string);
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
	if (rcvs == NULL)
		return;
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

	VERIFY(var != NULL);
	VERIFY(var->cv_scope != NULL);
	VERIFY(out != NULL);

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
	    (unsigned char *)val, -1, 0, 0);
	if (rc != 1) {
		/*
		 * If we failed to add it using MBSTRING_ASC, it might be
		 * because it's a legacy name component that breaks some rules
		 * (like country attributes longer than 3 chars). We'll try to
		 * add these without validation by giving the type argument
		 * as a specific type.
		 */
		int type;
		switch (nid) {
		case NID_domainComponent:
		case NID_pkcs9_emailAddress:
			type = V_ASN1_IA5STRING;
			break;
		default:
			type = V_ASN1_PRINTABLESTRING;
		}
		rc = X509_NAME_add_entry_by_NID(name, nid, type,
		    (unsigned char *)val, -1, 0, 0);
	}
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
	for (i = max - 1; i < max; --i) {
		X509_NAME_ENTRY *ent = X509_NAME_get_entry(name, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ent);
		ASN1_STRING *val = X509_NAME_ENTRY_get_data(ent);
		int nid;
		const char *name = NULL;

		nid = OBJ_obj2nid(obj);
		if (nid != NID_undef) {
			name = OBJ_nid2sn(nid);
			if (name == NULL)
				name = OBJ_nid2ln(nid);
			if (name != NULL)
				strlcpy(nmbuf, name, sizeof (nmbuf));
		}
		if (name == NULL) {
			rc = OBJ_obj2txt(nmbuf, sizeof (nmbuf), obj, 0);
			if (rc == -1) {
				make_sslerrf(err, "OBJ_obj2txt", "Failed to convert "
				    "DN entry %u", i);
				sshbuf_free(buf);
				return (err);
			}
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

		if (i != 0) {
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

void
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

char *
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

struct varval *
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

			VERIFY(vv->vv_string == NULL);
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
	VERIFY(vv->vv_string == NULL);
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

	VERIFY(rcs != NULL);

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

boolean_t
cert_var_defined(const struct cert_var *cv)
{
	while (cv->cv_value == NULL && cv->cv_parent != NULL)
		cv = cv->cv_parent;
	return (cv->cv_value != NULL);
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

static errf_t *
populate_common(struct cert_var_scope *cs, X509 *cert, char *basic, char *ku,
    char *eku)
{
	errf_t *err;
	char *lifetime, *dnstr, *policies = NULL;
	unsigned long lifetime_secs;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	X509_NAME *subj;
	CONF *config = NULL;

	err = scope_eval(cs, "lifetime", &lifetime);
	if (err != ERRF_OK) {
		return (errf("MissingParameter", err, "certificate 'lifetime' "
		    "is required"));
	}
	err = parse_lifetime(lifetime, &lifetime_secs);
	if (err != NULL)
		return (err);
	free(lifetime);

	VERIFY(X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL);
	VERIFY(X509_gmtime_adj(X509_get_notAfter(cert), lifetime_secs) != NULL);

	subj = X509_NAME_new();
	VERIFY(subj != NULL);

	err = scope_eval(cs, "dn", &dnstr);
	if (err != ERRF_OK) {
		X509_NAME_free(subj);
		return (errf("MissingParameter", err, "certificate 'dn' "
		    "is required"));
	}

	err = parse_dn(dnstr, subj);
	if (err != ERRF_OK) {
		X509_NAME_free(subj);
		return (errf("InvalidDN", err, "failed to parse certificate "
		    "'dn' value: '%s'", dnstr));
	}
	free(dnstr);

	VERIFY(X509_set_subject_name(cert, subj) == 1);
	X509_NAME_free(subj);

	err = scope_eval(cs, "cert_policies", &policies);
	if (err == ERRF_OK) {
		OPENSSL_config(NULL);

		err = load_ossl_config("piv_ca", cs, &config);
		if (err != ERRF_OK)
			return (err);

		X509V3_set_nconf(&x509ctx, config);
	} else {
		X509V3_set_ctx_nodb(&x509ctx);
	}
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	if (basic != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
		    (char *)basic);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing basicConstraints extension");
			return (err);
		}
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	if (ku != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage,
		    (char *)ku);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing keyUsage extension");
			return (err);
		}
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	if (eku != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_ext_key_usage,
		    (char *)eku);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing extKeyUsage extension");
			return (err);
		}
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	if (policies != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx,
		    NID_certificate_policies, (char *)policies);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing certificatePolicies extension");
			return (err);
		}
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
		free(policies);
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
		char *saveptr = NULL, *token;

		token = strtok_r(upn, ",; ", &saveptr);
		while (token != NULL) {
			obj = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.3", 1);
			VERIFY(obj != NULL);

			str = ASN1_UTF8STRING_new();
			VERIFY(str != NULL);
			VERIFY(ASN1_STRING_set(str, token, -1) == 1);

			typ = ASN1_TYPE_new();
			VERIFY(typ != NULL);
			ASN1_TYPE_set(typ, V_ASN1_UTF8STRING, str);

			gn = GENERAL_NAME_new();
			VERIFY(gn != NULL);
			VERIFY(GENERAL_NAME_set0_othername(gn, obj, typ) == 1);
			VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);

			token = strtok_r(NULL, ",; ", &saveptr);
		}
	}
	free(upn);

	if (krbpn != NULL) {
		obj = OBJ_txt2obj("1.3.6.1.5.2.2", 1);
		VERIFY(obj != NULL);

		princ = v2i_PKINIT_PRINC(NULL, krbpn);
		if (princ == NULL) {
			err = errf("SyntaxError", NULL, "failed to "
			    "parse krb5 principal name '%s'", krbpn);
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
		VERIFY(GENERAL_NAME_set0_othername(gn, obj, typ) == 1);
		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	}
	free(krbpn);

	return (ERRF_OK);
}

static errf_t *
gen_sid_ext(struct cert_var_scope *cs, X509_EXTENSION **out)
{
	errf_t *err;
	X509_EXTENSION *ext = NULL;
	char *str = NULL;
	struct sshbuf *buf = NULL, *sbuf = NULL;
	int rc;
	uint i;
	ASN1_OCTET_STRING *asn1_str = NULL;
	ASN1_OBJECT *obj = NULL;
	ASN1_TYPE *typ = NULL;
	uint8_t v;
	uint64_t v64;
	uint32_t subauth;
	uint64_t idauth;
	STACK_OF(GENERAL_NAME) *gns = NULL;
	GENERAL_NAME *gn = NULL;
	uint8_t *derbuf = NULL;
	size_t len;

	err = scope_eval(cs, "ad_sid", &str);
	if (err != ERRF_OK) {
		errf_free(err);
		*out = NULL;
		err = ERRF_OK;
		goto out;
	}

	if (strncmp(str, "S-1-", 4) != 0) {
		buf = sshbuf_new();
		VERIFY(buf != NULL);

		sbuf = sshbuf_new();
		VERIFY(sbuf != NULL);

		err = sshbuf_b16tod(str, buf);
		if (err != ERRF_OK) {
			errf_free(err);
			rc = sshbuf_b64tod(buf, str);
			if (rc != 0) {
				err = errf("InvalidFormat",
				    ssherrf("sshbuf_b64tod", rc),
				    "Failed to parse 'ad_sid' value as a "
				    "string SID, hex or base64: '%s'", str);
				goto out;
			}
		}
		free(str);
		str = NULL;

		if ((rc = sshbuf_get_u64(buf, &v64))) {
			err = ssherrf("sshbuf_get_u64", rc);
			goto out;
		}

		v = (v64 >> 56) & 0xff;
		if (v != 1) {
			err = errf("InvalidFormat", NULL, "base64-encoded "
			    "SID should start with a 1-byte (started with "
			    "%u instead)", v);
			goto out;
		}
		v = (v64 >> 48) & 0xff;
		if (v > 64) {
			err = errf("InvalidFormat", NULL, "base64-encoded "
			    "SID should have <64 subauths (has %u)", v);
			goto out;
		}
		idauth = v64 & ((1ULL << 48) - 1);

		rc = sshbuf_putf(sbuf, "S-1-%" PRIu64, idauth);
		if (rc != 0) {
			err = ssherrf("sshbuf_putf", rc);
			goto out;
		}

		for (i = 0; i < v; ++i) {
			/*
			 * subauths are little-endian, so we'll read them in
			 * by hand (sshbuf_get_u32 always reads big-endian)
			 */
			const uint8_t *p = sshbuf_ptr(buf);
			rc = sshbuf_consume(buf, 4);
			if (rc != 0) {
				err = ssherrf("sshbuf_consume", rc);
				goto out;
			}
			subauth = (uint32_t)p[0] | (uint32_t)(p[1] << 8) |
			    (uint32_t)(p[2] << 16) | (uint32_t)(p[3] << 24);

			rc = sshbuf_putf(sbuf, "-%u", subauth);
			if (rc != 0) {
				err = ssherrf("sshbuf_putf", rc);
				goto out;
			}
		}

		str = sshbuf_dup_string(sbuf);
	}

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	asn1_str = ASN1_OCTET_STRING_new();
	VERIFY(asn1_str != NULL);
	VERIFY(ASN1_STRING_set(asn1_str, str, -1) == 1);

	obj = OBJ_txt2obj("1.3.6.1.4.1.311.25.2.1", 1);
	if (obj == NULL) {
		make_sslerrf(err, "OBJ_txt2obj", "obtaining NID for SID ext");
		goto out;
	}

	typ = ASN1_TYPE_new();
	VERIFY(typ != NULL);
	ASN1_TYPE_set(typ, V_ASN1_OCTET_STRING, asn1_str);
	asn1_str = NULL;

	gn = GENERAL_NAME_new();
	VERIFY(gn != NULL);
	GENERAL_NAME_set0_othername(gn, obj, typ);
	typ = NULL;
	obj = NULL;
	VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	gn = NULL;

	obj = OBJ_txt2obj("1.3.6.1.4.1.311.25.2", 1);
	if (obj == NULL) {
		make_sslerrf(err, "OBJ_txt2obj", "obtaining NID for SID ext");
		goto out;
	}

	rc = i2d_GENERAL_NAMES(gns, &derbuf);
	if (rc < 1) {
		make_sslerrf(err, "i2d_GENERAL_NAMES", "building SID ext");
		goto out;
	}
	len = rc;

	asn1_str = ASN1_OCTET_STRING_new();
	VERIFY(asn1_str != NULL);
	VERIFY(ASN1_STRING_set(asn1_str, derbuf, len) == 1);

	ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, asn1_str);
	VERIFY(ext != NULL);

	*out = ext;
	ext = NULL;
	err = ERRF_OK;

out:
	free(str);
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	ASN1_OCTET_STRING_free(asn1_str);
	ASN1_OBJECT_free(obj);
	X509_EXTENSION_free(ext);
	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
	GENERAL_NAME_free(gn);
	ASN1_TYPE_free(typ);
	free(derbuf);
	return (err);
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

	err = gen_sid_ext(cs, &ext);
	if (err != ERRF_OK)
		return (err);
	if (ext != NULL) {
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	}

	return (ERRF_OK);
}

static errf_t *
populate_user_auth(struct cert_var_scope *cs, X509 *cert)
{
	errf_t *err;
	char *upn, *krbpn, *aduser;
	char eku[128], ku[64];
	boolean_t is_ad_user = B_FALSE;
	EVP_PKEY *pkey;

	ku[0] = 0;
	xstrlcat(ku, "critical,digitalSignature", sizeof (ku));

	eku[0] = 0;
	xstrlcat(eku, "clientAuth", sizeof (eku));

	pkey = X509_get0_pubkey(cert);
	if (pkey != NULL && EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA)
		xstrlcat(ku, ",keyEncipherment", sizeof (ku));

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
	err = scope_eval(cs, "is_ad_user", &aduser);
	if (err != ERRF_OK) {
		errf_free(err);
		aduser = NULL;
	}
	if (upn != NULL)
		is_ad_user = B_TRUE;
	if (aduser != NULL && (strcasecmp(aduser, "yes") == 0 ||
	    strcasecmp(aduser, "true") == 0)) {
		is_ad_user = B_TRUE;
	}

	if (is_ad_user)
		xstrlcat(eku, ",1.3.6.1.4.1.311.20.2.2", sizeof (eku));
	if (krbpn != NULL)
		xstrlcat(eku, ",1.3.6.1.5.2.3.4", sizeof (eku));;
	free(upn);
	free(aduser);
	free(krbpn);

	err = populate_common(cs, cert, "critical,CA:FALSE", ku, eku);
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
		eku = "1.3.6.1.4.1.311.10.3.4,1.3.6.1.4.1.311.10.3.4.1,"
		    "1.3.6.1.4.1.311.67.1.1,1.3.6.1.4.1.311.67.1.2";
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
build_smime_caps(X509_EXTENSION **out)
{
	X509_EXTENSION *ext = NULL;
	STACK_OF(X509_ALGOR) *algs = NULL;
	X509_ALGOR *alg = NULL;
	unsigned char *smder = NULL;
	size_t smlen;
	int rc;
	errf_t *err;
	ASN1_OCTET_STRING *data = NULL;
	ASN1_OBJECT *obj = NULL;
	uint i;
	int nids[] = {
	    NID_aes_256_cbc, NID_id_aes256_wrap,
	    NID_aes_128_cbc, NID_id_aes128_wrap,
	    NID_des_ede3_cbc
	};

	algs = sk_X509_ALGOR_new_null();
	VERIFY(algs != NULL);

	for (i = 0; i < (sizeof (nids) / sizeof (int)); ++i) {
		obj = OBJ_nid2obj(nids[i]);
		if (obj == NULL) {
			make_sslerrf(err, "OBJ_nid2obj",
			    "converting alg to obj");
			goto out;
		}

		alg = X509_ALGOR_new();
		VERIFY(alg != NULL);
		rc = X509_ALGOR_set0(alg, obj, V_ASN1_UNDEF, NULL);
		if (rc != 1) {
			make_sslerrf(err, "X509_ALGOR_set0",
			    "setting algorithm info");
			goto out;
		}
		obj = NULL;	/* X509_ALGOR_set0 takes ownership */

		VERIFY(sk_X509_ALGOR_push(algs, alg) != 0);
		alg = NULL;	/* sk_X509_ALGOR_push takes ownership */
	}

	rc = i2d_X509_ALGORS(algs, &smder);
	if (rc <= 0) {
		make_sslerrf(err, "i2d_X509_ALGORS", "while generating S/MIME "
		    "capabilities extension");
		goto out;
	}
	smlen = rc;

	data = ASN1_OCTET_STRING_new();
	VERIFY(data != NULL);
	VERIFY(ASN1_STRING_set(data, smder, smlen) == 1);

	ext = X509_EXTENSION_create_by_NID(NULL, NID_SMIMECapabilities, 0,
	    data);
	VERIFY(ext != NULL);

	*out = ext;
	ext = NULL;
	err = ERRF_OK;

out:
	sk_X509_ALGOR_pop_free(algs, X509_ALGOR_free);
	OPENSSL_free(smder);
	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(data);
	ASN1_OBJECT_free(obj);
	X509_ALGOR_free(alg);
	return (err);
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
	    "critical,digitalSignature,keyAgreement,keyEncipherment",
	    "clientAuth,emailProtection,"
	    "1.3.6.1.4.1.311.3.10.3.12,"        /* MS doc signing */
	    "1.2.840.113583.1.1.5"              /* Adobe doc signing */);
	if (err != ERRF_OK)
		return (err);

	cfglen = strlen(email) + 8;
	cfg = calloc(cfglen, 1);
	VERIFY(cfg != NULL);
	xstrlcat(cfg, "email:", cfglen);
	xstrlcat(cfg, email, cfglen);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_subject_alt_name, cfg);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	err = build_smime_caps(&ext);
	if (err != ERRF_OK)
		return (err);
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
	char *upn, *krbpn, *dns_name, *replguid, *is_dc_str, *ike;
	boolean_t is_dc = B_FALSE;
	char *eku, *ku;
	X509_EXTENSION *ext;
	GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) *gns;
	char *saveptr;
	char *tkn;
	struct sshbuf *ekubuf;
	struct sshbuf *kubuf;
	EVP_PKEY *pubkey;

	ekubuf = sshbuf_new();
	VERIFY(ekubuf != NULL);

	kubuf = sshbuf_new();
	VERIFY(kubuf != NULL);

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
	err = scope_eval(cs, "ad_repl_guid", &replguid);
	if (err != ERRF_OK) {
		errf_free(err);
		replguid = NULL;
	}

	err = scope_eval(cs, "is_ad_dc", &is_dc_str);
	if (err != ERRF_OK) {
		errf_free(err);
		is_dc_str = NULL;
	}
	if (is_dc_str != NULL && (
	    strcasecmp(is_dc_str, "yes") == 0 ||
	    strcasecmp(is_dc_str, "true") == 0)) {
		is_dc = B_TRUE;
	}
	free(is_dc_str);

	err = scope_eval(cs, "is_ike_server", &ike);
	if (err != ERRF_OK) {
		errf_free(err);
		ike = NULL;
	}

	VERIFY0(sshbuf_putf(kubuf, "critical,digitalSignature"));

	pubkey = X509_get0_pubkey(cert);

	if (replguid != NULL || is_dc ||
	    (pubkey != NULL && EVP_PKEY_base_id(pubkey) == EVP_PKEY_RSA)) {
		VERIFY0(sshbuf_putf(kubuf, ",keyEncipherment"));
	}

	VERIFY0(sshbuf_putf(ekubuf, "clientAuth,serverAuth"));
	if (upn != NULL) {
		VERIFY0(sshbuf_putf(ekubuf, ",1.3.6.1.4.1.311.20.2.2"));
	}
	if (is_dc && krbpn != NULL) {
		VERIFY0(sshbuf_putf(ekubuf, ",1.3.6.1.5.2.3.5"));
	}
	if (replguid != NULL) {
		VERIFY0(sshbuf_putf(ekubuf, ",1.3.6.1.4.1.311.21.19"));
	}
	if (ike != NULL) {
		VERIFY0(sshbuf_putf(ekubuf, ",1.3.6.1.5.5.8.2.2"));
	}
	free(upn);
	free(krbpn);
	free(ike);

	eku = sshbuf_dup_string(ekubuf);
	sshbuf_free(ekubuf);
	ku = sshbuf_dup_string(kubuf);
	sshbuf_free(kubuf);

	err = populate_common(cs, cert, "critical,CA:FALSE", ku, eku);
	if (err != ERRF_OK)
		return (err);
	free(eku);
	free(ku);

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
	if (replguid != NULL) {
		GENERAL_NAME *gn;
		ASN1_OBJECT *obj;
		ASN1_OCTET_STRING *str;
		ASN1_TYPE *typ;
		struct sshbuf *guidbuf;

		guidbuf = sshbuf_new();
		VERIFY(guidbuf != NULL);
		err = sshbuf_b16tod(replguid, guidbuf);
		if (err != ERRF_OK) {
			return (errf("SyntaxError", NULL, "Failed to parse "
			    "ad_repl_guid: '%s'", replguid));
		}

		obj = OBJ_txt2obj("1.3.6.1.4.1.311.25.1", 1);
		VERIFY(obj != NULL);

		str = ASN1_OCTET_STRING_new();
		VERIFY(str != NULL);
		VERIFY(ASN1_STRING_set(str, sshbuf_ptr(guidbuf),
		    sshbuf_len(guidbuf)) == 1);

		typ = ASN1_TYPE_new();
		VERIFY(typ != NULL);
		ASN1_TYPE_set(typ, V_ASN1_OCTET_STRING, str);

		gn = GENERAL_NAME_new();
		VERIFY(gn != NULL);
		VERIFY(GENERAL_NAME_set0_othername(gn, obj, typ) == 1);
		VERIFY(sk_GENERAL_NAME_push(gns, gn) != 0);
	}
	free(replguid);

	ext = X509V3_EXT_i2d(NID_subject_alt_name, 1, gns);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);

	free(dns_name);

	return (ERRF_OK);
}

static errf_t *
populate_dn_only(struct cert_var_scope *cs, X509 *cert)
{
	return (populate_common(cs, cert, NULL, NULL, NULL));
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
	EVP_PKEY *pubkey = NULL;
	ASN1_OCTET_STRING *kid = NULL;
	int rc;

	OPENSSL_config(NULL);

	err = load_ossl_config("piv_ca", cs, &config);
	if (err != ERRF_OK) {
		err = errf("OpenSSLConfigVarsError", err, "Failed to process "
		    "OpenSSL config variables");
		goto out;
	}

	X509V3_set_nconf(&x509ctx, config);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	xstrlcpy(basic, "critical,CA:TRUE", sizeof (basic));
	err = scope_eval(cs, "path_len", &pathlen);
	if (err == ERRF_OK) {
		xstrlcat(basic, ",pathlen:", sizeof (basic));
		xstrlcat(basic, pathlen, sizeof (basic));
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
		X509_EXTENSION_set_critical(ext, 0);
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
	} else {
		errf_free(err);
	}

	pubkey = X509_get_pubkey(cert);
	if (pubkey != NULL) {
		err = pkey_key_id(pubkey, &kid);
		if (err != ERRF_OK)
			goto out;

		rc = X509_add1_ext_i2d(cert, NID_subject_key_identifier, kid, 0,
		    X509V3_ADD_REPLACE);
		if (rc != 1) {
			make_sslerrf(err, "X509_add1_ext_i2d", "adding subject "
			    "key id");
			goto out;
		}
	}

	err = ERRF_OK;

out:
	ASN1_OCTET_STRING_free(kid);
	EVP_PKEY_free(pubkey);
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
	char *dnstr, *policies = NULL;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	X509_NAME *subj;
	CONF *config = NULL;

	subj = X509_NAME_new();
	VERIFY(subj != NULL);

	err = scope_eval(cs, "dn", &dnstr);
	if (err != ERRF_OK) {
		X509_NAME_free(subj);
		return (errf("MissingParameter", err, "certificate 'dn' "
		    "is required"));
	}

	err = parse_dn(dnstr, subj);
	if (err != ERRF_OK) {
		X509_NAME_free(subj);
		return (errf("InvalidDN", err, "failed to parse certificate "
		    "'dn' value: '%s'", dnstr));
	}
	free(dnstr);

	VERIFY(X509_REQ_set_subject_name(req, subj) == 1);
	X509_NAME_free(subj);

	err = scope_eval(cs, "cert_policies", &policies);
	if (err == ERRF_OK) {
		OPENSSL_config(NULL);

		err = load_ossl_config("piv_ca", cs, &config);
		if (err != ERRF_OK)
			return (err);

		X509V3_set_nconf(&x509ctx, config);
	} else {
		X509V3_set_ctx_nodb(&x509ctx);
	}
	X509V3_set_ctx(&x509ctx, NULL, NULL, req, NULL, 0);

	if (basic != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
		    (char *)basic);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing basicConstraints extension");
			return (err);
		}
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	}

	if (ku != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage,
		    (char *)ku);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing keyUsage extension");
			return (err);
		}
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	}

	if (eku != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_ext_key_usage,
		    (char *)eku);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing extKeyUsage extension");
			return (err);
		}
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	}

	if (policies != NULL) {
		ext = X509V3_EXT_conf_nid(NULL, &x509ctx,
		    NID_certificate_policies, (char *)policies);
		if (ext == NULL) {
			make_sslerrf(err, "X509V3_EXT_conf_nid",
			    "parsing certificatePolicies extension");
			return (err);
		}
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
		free(policies);
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

	err = gen_sid_ext(cs, &ext);
	if (err != ERRF_OK)
		return (err);
	if (ext != NULL)
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

	return (ERRF_OK);
}

static errf_t *
rpopulate_dn_only(struct cert_var_scope *cs, X509_REQ *req)
{
	STACK_OF(X509_EXTENSION) *exts;
	errf_t *err;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = rpopulate_common(cs, req, exts, NULL, NULL, NULL);
	if (err != ERRF_OK)
		return (err);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	return (ERRF_OK);
}

static errf_t *
rpopulate_user_auth(struct cert_var_scope *cs, X509_REQ *req)
{
	errf_t *err;
	char *upn = NULL, *krbpn = NULL, *aduser = NULL;
	char eku[128];
	char ku[64];
	STACK_OF(X509_EXTENSION) *exts;
	boolean_t is_ad_user = B_FALSE;
	EVP_PKEY *pkey;

	eku[0] = 0;
	xstrlcat(eku, "clientAuth", sizeof (eku));

	ku[0] = 0;
	xstrlcat(ku, "critical,digitalSignature", sizeof (ku));

	pkey = X509_REQ_get0_pubkey(req);
	if (pkey != NULL && EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA)
		xstrlcat(ku, ",keyEncipherment", sizeof (ku));

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
	err = scope_eval(cs, "is_ad_user", &aduser);
	if (err != ERRF_OK) {
		errf_free(err);
		aduser = NULL;
	}
	if (upn != NULL)
		is_ad_user = B_TRUE;
	if (aduser != NULL && (strcasecmp(aduser, "yes") == 0 ||
	    strcasecmp(aduser, "true") == 0)) {
		is_ad_user = B_TRUE;
	}

	if (is_ad_user)
		xstrlcat(eku, ",1.3.6.1.4.1.311.20.2.2", sizeof (eku));
	if (krbpn != NULL)
		xstrlcat(eku, ",1.3.6.1.5.2.3.4", sizeof (eku));

	free(upn);
	free(krbpn);
	free(aduser);

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE", ku, eku);
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
		eku = "1.3.6.1.4.1.311.10.3.4,1.3.6.1.4.1.311.10.3.4.1,"
		    "1.3.6.1.4.1.311.67.1.1,1.3.6.1.4.1.311.67.1.2";
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
	    "1.3.6.1.4.1.311.3.10.3.12,"        /* MS doc signing */
	    "1.2.840.113583.1.1.5"              /* Adobe doc signing */);
	if (err != ERRF_OK)
		return (err);

	cfglen = strlen(email) + 8;
	cfg = calloc(cfglen, 1);
	VERIFY(cfg != NULL);
	xstrlcat(cfg, "email:", cfglen);
	xstrlcat(cfg, email, cfglen);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, NULL, NULL, req, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_subject_alt_name, cfg);
	VERIFY(ext != NULL);
	VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);

	err = build_smime_caps(&ext);
	if (err != ERRF_OK)
		return (err);
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
	char *upn, *krbpn, *dns_name, *ike, *is_dc_str;
	boolean_t is_dc = B_FALSE;
	char eku[128];
	char ku[64];
	X509_EXTENSION *ext;
	GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) *gns;
	char *saveptr;
	char *tkn;
	STACK_OF(X509_EXTENSION) *exts;
	EVP_PKEY *pkey;

	eku[0] = 0;
	xstrlcat(eku, "clientAuth,serverAuth", sizeof (eku));

	ku[0] = 0;
	xstrlcat(ku, "critical,digitalSignature", sizeof (ku));

	pkey = X509_REQ_get0_pubkey(req);
	if (pkey != NULL && EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA)
		xstrlcat(ku, ",keyEncipherment", sizeof (ku));

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	err = scope_eval(cs, "dns_name", &dns_name);
	if (err != ERRF_OK) {
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		return (err);
	}

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
	err = scope_eval(cs, "is_ike_server", &ike);
	if (err != ERRF_OK) {
		errf_free(err);
		ike = NULL;
	}

	err = scope_eval(cs, "is_ad_dc", &is_dc_str);
	if (err != ERRF_OK) {
		errf_free(err);
		is_dc_str = NULL;
	}
	if (is_dc_str != NULL && (
	    strcasecmp(is_dc_str, "yes") == 0 ||
	    strcasecmp(is_dc_str, "true") == 0)) {
		is_dc = B_TRUE;
	}
	free(is_dc_str);

	if (upn != NULL)
		xstrlcat(eku, ",1.3.6.1.4.1.311.20.2.2", sizeof (eku));
	if (krbpn != NULL && is_dc)
		xstrlcat(eku, ",1.3.6.1.5.2.3.5", sizeof (eku));
	if (ike != NULL && strcasecmp(ike, "yes") == 0)
		xstrlcat(eku, ",1.3.6.1.5.5.8.2.2", sizeof (eku));

	free(upn);
	free(krbpn);
	free(ike);

	err = rpopulate_common(cs, req, exts, "critical,CA:FALSE", ku, eku);
	if (err != ERRF_OK) {
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		return (err);
	}

	gns = sk_GENERAL_NAME_new_null();
	VERIFY(gns != NULL);

	err = add_common_princs(cs, gns);
	if (err != ERRF_OK) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		return (err);
	}

	tkn = strtok_r(dns_name, "; ", &saveptr);
	if (tkn == NULL) {
		sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
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
	EVP_PKEY *pubkey = NULL;
	ASN1_OCTET_STRING *kid = NULL;
	int rc;

	exts = sk_X509_EXTENSION_new_null();
	VERIFY(exts != NULL);

	OPENSSL_config(NULL);

	err = load_ossl_config("piv_ca", cs, &config);
	if (err != ERRF_OK)
		goto out;

	X509V3_set_nconf(&x509ctx, config);
	X509V3_set_ctx(&x509ctx, NULL, NULL, req, NULL, 0);

	strlcpy(basic, "critical,CA:TRUE", sizeof (basic));
	err = scope_eval(cs, "path_len", &pathlen);
	if (err == ERRF_OK) {
		xstrlcat(basic, ",pathlen:", sizeof (basic));
		xstrlcat(basic, pathlen, sizeof (basic));
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
		X509_EXTENSION_set_critical(ext, 0);
		VERIFY(sk_X509_EXTENSION_push(exts, ext) != 0);
	} else {
		errf_free(err);
	}

	pubkey = X509_REQ_get_pubkey(req);
	if (pubkey != NULL) {
		err = pkey_key_id(pubkey, &kid);
		if (err != ERRF_OK)
			goto out;

		rc = X509V3_add1_i2d(&exts, NID_subject_key_identifier, kid,
		    0, X509V3_ADD_REPLACE);
		if (rc != 1) {
			make_sslerrf(err, "X509V3_add1_i2d", "generating "
			    " subject key id");
			goto out;
		}
	}

	VERIFY(X509_REQ_add_extensions(req, exts) == 1);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	err = ERRF_OK;

out:
	ASN1_OCTET_STRING_free(kid);
	EVP_PKEY_free(pubkey);
	free(namecons);
	free(pathlen);
	free(eku);
	NCONF_free(config);

	return (err);
}

errf_t *
sshkey_to_evp_pkey(const struct sshkey *pubkey, EVP_PKEY **ppkey)
{
	errf_t *err = ERRF_OK;
	EVP_PKEY *pkey = NULL;
	RSA *rsa;
	EC_KEY *ec;

	pkey = EVP_PKEY_new();
	VERIFY(pkey != NULL);

	if (pubkey->type == KEY_RSA) {
		rsa = EVP_PKEY_get1_RSA(pubkey->pkey);
		EVP_PKEY_set1_RSA(pkey, rsa);
	} else if (pubkey->type == KEY_ECDSA) {
		ec = EVP_PKEY_get1_EC_KEY(pubkey->pkey);
		EVP_PKEY_set1_EC_KEY(pkey, ec);
	} else if (pubkey->type == KEY_ED25519) {
		pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
		    NULL, pubkey->ed25519_pk, 32);
	} else {
		err = errf("InvalidKeyType", NULL, "invalid key type: %d",
		    pubkey->type);
		goto out;
	}

	*ppkey = pkey;
	pkey = NULL;
	err = ERRF_OK;

out:
	EVP_PKEY_free(pkey);
	return (err);
}

static errf_t *
set_pkey_from_sshkey(struct sshkey *pubkey, struct piv_token *tkn,
    EVP_PKEY **pkey, enum sshdigest_types *wantalg, int *nid)
{
	errf_t *err = ERRF_OK;
	uint i;

	if ((err = sshkey_to_evp_pkey(pubkey, pkey)))
		return (err);

	if (pubkey->type == KEY_RSA) {
		*nid = NID_sha256WithRSAEncryption;
		*wantalg = SSH_DIGEST_SHA256;

	} else if (pubkey->type == KEY_ECDSA) {
		boolean_t haveSha256 = B_FALSE;
		boolean_t haveSha1 = B_FALSE;

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

	} else if (pubkey->type == KEY_ED25519) {
		*nid = NID_ED25519;
		*wantalg = SSH_DIGEST_SHA512;

	} else {
		err = errf("InvalidKeyType", NULL, "invalid key type: %d",
		    pubkey->type);
		goto out;
	}

out:

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

errf_t *
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
agent_sign_crl(int fd, struct sshkey *pubkey, X509_CRL *crl)
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

	rc = X509_CRL_add1_ext_i2d(crl, NID_authority_key_identifier, akid, 0,
	    X509V3_ADD_REPLACE);
	if (rc != 1) {
		make_sslerrf(err, "X509_CRL_add1_ext_i2d", "adding authority "
		    "key id");
		goto out;
	}

	algobj = OBJ_nid2obj(nid);
	if (algobj == NULL) {
		make_sslerrf(err, "OBJ_nid2obj", "setting signing algo");
		goto out;
	}

	X509_CRL_get0_signature(crl, (const ASN1_BIT_STRING **)&asnsig,
	    (const X509_ALGOR **)&algor);

	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	algor = (X509_ALGOR *)X509_CRL_get0_tbs_sigalg(crl);
	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	tbslen = i2d_re_X509_CRL_tbs(crl, &tbs);
	if (tbslen == 0) {
		make_sslerrf(err, "i2d_re_X509_CRL_tbs",
		    "encoding to-be-signed CRL");
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
piv_sign_crl(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509_CRL *crl)
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
	size_t tbslen, siglen = 0;
	AUTHORITY_KEYID *akid = NULL;
	ASN1_OCTET_STRING *kid = NULL;

	VERIFY(pubkey != NULL);

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

	rc = X509_CRL_add1_ext_i2d(crl, NID_authority_key_identifier, akid, 0,
	    X509V3_ADD_REPLACE);
	if (rc != 1) {
		make_sslerrf(err, "X509_CRL_add1_ext_i2d", "adding authority "
		    "key id");
		goto out;
	}

	algobj = OBJ_nid2obj(nid);
	if (algobj == NULL) {
		make_sslerrf(err, "OBJ_nid2obj", "setting signing algo");
		goto out;
	}

	X509_CRL_get0_signature(crl, (const ASN1_BIT_STRING **)&asnsig,
	    (const X509_ALGOR **)&algor);

	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	algor = (X509_ALGOR *)X509_CRL_get0_tbs_sigalg(crl);
	rc = X509_ALGOR_set0(algor, algobj,
	    pubkey->type == KEY_RSA ? V_ASN1_NULL : V_ASN1_UNDEF, NULL);
	if (rc != 1) {
		make_sslerrf(err, "X509_ALGOR_set0", "setting signing algo");
		goto out;
	}

	tbslen = i2d_re_X509_CRL_tbs(crl, &tbs);
	if (tbslen == 0) {
		make_sslerrf(err, "i2d_re_X509_CRL_tbs",
		    "encoding to-be-signed CRL");
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
	freezero(sig, siglen);
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
	size_t tbslen, siglen = 0;

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

				xstrlcpy(namebuf, "_ossl_config:",
				    sizeof (namebuf));
				xstrlcat(namebuf, fname, sizeof (namebuf));
				name = namebuf;

				cvv = scope_lookup(cs, namebuf, 1);
				VERIFY(cvv != NULL);

				err = cert_var_set(cvv, buf);
				if (err != ERRF_OK)
					goto out;

				prefix[0] = '\0';

			} else if (name[0] == '@') {
				cvv = scope_lookup(cs, name, 1);
				xstrlcpy(prefix, "[", sizeof (prefix));
				xstrlcat(prefix, name + 1, sizeof (prefix));
				xstrlcat(prefix, "]\n", sizeof (prefix));

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

errf_t *
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

errf_t *
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
