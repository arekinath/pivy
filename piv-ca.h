/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2022 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

/*
 * Shared utility functions for populating certificates
 */

#if !defined(_PIV_CA_H)
#define _PIV_CA_H

#include <sys/types.h>
#include <stdint.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"

#include "errf.h"
#include "piv.h"
#include "ebox.h"

/*
 * Certificate templates and variable expansion
 */

struct cert_var_scope;
struct cert_var;
struct cert_tpl;

enum requirement_type {
	REQUIRED_FOR_CERT,
	REQUIRED_FOR_CERT_REQUEST
};

const struct cert_tpl	*cert_tpl_find(const char *name);
const struct cert_tpl	*cert_tpl_first(void);
const struct cert_tpl	*cert_tpl_next(const struct cert_tpl *);
const char		*cert_tpl_name(const struct cert_tpl *);
const char		*cert_tpl_help(const struct cert_tpl *);

struct cert_var		*cert_var_next(struct cert_var *);
void			 cert_var_free_all(struct cert_var *);

const char		*cert_var_name(const struct cert_var *);
const char		*cert_var_help(const struct cert_var *);
void			 cert_var_set_help(struct cert_var *, const char *);
char			*cert_var_raw_value(const struct cert_var *);
char			*cert_var_value(const struct cert_var *);
errf_t			*cert_var_set(struct cert_var *, const char *);
errf_t			*cert_var_eval(struct cert_var *var, char **out);
boolean_t		 cert_var_defined(const struct cert_var *);
int			 cert_var_required(const struct cert_var *,
    enum requirement_type);
void			 cert_var_set_required(struct cert_var *,
    enum requirement_type);

void			*cert_var_alloc_private(struct cert_var *, size_t);
void			*cert_var_private(struct cert_var *);
void			 cert_var_free_private(struct cert_var *);

struct cert_var		*cert_tpl_vars(const struct cert_tpl *);

struct cert_var_scope	*scope_new_root(void);
struct cert_var_scope	*scope_new_empty(struct cert_var_scope *parent);
struct cert_var_scope	*scope_new_for_tpl(struct cert_var_scope *parent,
    const struct cert_tpl *tpl);
struct cert_var_scope	*scope_parent(struct cert_var_scope *scope);
struct cert_var		*scope_lookup(struct cert_var_scope *scope,
    const char *name, int undef);
errf_t			*scope_set(struct cert_var_scope *scope,
    const char *name, const char *value);
errf_t			*scope_eval(struct cert_var_scope *scope,
    const char *name, char **out);
void			 scope_free_root(struct cert_var_scope *scope);

errf_t			*cert_tpl_populate(const struct cert_tpl *tpl,
    struct cert_var_scope *scope, X509 *cert);
errf_t			*cert_tpl_populate_req(const struct cert_tpl *tpl,
    struct cert_var_scope *cvs, X509_REQ *req);

struct cert_var		*scope_all_vars(struct cert_var_scope *scope);
struct cert_var		*scope_undef_vars(struct cert_var_scope *scope);

errf_t	*sshkey_to_evp_pkey(const struct sshkey *pubkey, EVP_PKEY **ppkey);

errf_t	*piv_selfsign_cert(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509 *cert);
errf_t	*piv_sign_cert(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509 *cert);
errf_t	*piv_sign_cert_req(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509_REQ *req);
errf_t	*agent_sign_cert(int fd, struct sshkey *pubkey, X509 *cert);

errf_t	*agent_sign_crl(int fd, struct sshkey *pubkey, X509_CRL *crl);
errf_t	*piv_sign_crl(struct piv_token *tkn, struct piv_slot *slot,
    struct sshkey *pubkey, X509_CRL *crl);

errf_t	*scope_populate_req(struct cert_var_scope *scope, X509_REQ *req);

/*
 * CA state and stuff
 */
struct ca;
struct ca_token_tpl;
struct ca_token_slot_tpl;
struct ca_cert_tpl;

struct ca_cert;
struct ca_token;
struct ca_crl;

struct ca_session;

struct ca_new_args;
struct provision_args;

enum ca_cert_type {
	CA_CERT_TOKEN,
	CA_CERT_INTERMEDIATE,
	CA_CERT_OTHER
};

enum ca_token_tpl_flags {
	CTTF_PUK_RAND		= (1<<0),	/* generate random puk */
	CTTF_ADMIN_KEY_RAND	= (1<<1),	/* generate a new admin key */
	CTTF_ADMIN_KEY_PINFO	= (1<<2),	/* store admin key in pinfo */
	CTTF_SIGN_CHUID		= (1<<3),	/* sign chuid file */
	CTTF_PINFO		= (1<<4)	/* add user details in pinfo */
};

enum ca_cert_tpl_flags {
	CCTF_SELF_SIGNED	= (1<<0),
	CCTF_ALLOW_REQS		= (1<<1),
	CCTF_COPY_DN		= (1<<2),
	CCTF_COPY_KP		= (1<<3),
	CCTF_COPY_SAN		= (1<<4),
	CCTF_COPY_OTHER_EXTS	= (1<<5),
	CCTF_KEY_BACKUP		= (1<<6),
	CCTF_HOST_KEYGEN	= (1<<7)
};

enum ca_ebox_type {
	CA_EBOX_PIN,
	CA_EBOX_OLD_PIN,
	CA_EBOX_PUK,
	CA_EBOX_KEY_BACKUP,
	CA_EBOX_ADMIN_KEY
};

struct ca_new_args	*cana_new(void);
void	 cana_initial_pin(struct ca_new_args *, const char *);
void	 cana_initial_puk(struct ca_new_args *, const char *);
void	 cana_initial_admin_key(struct ca_new_args *, enum piv_alg,
    const uint8_t *, size_t);
void	 cana_key_alg(struct ca_new_args *, enum piv_alg alg);
void	 cana_backup_tpl(struct ca_new_args *, const char *, struct ebox_tpl *);
void	 cana_pin_tpl(struct ca_new_args *, const char *, struct ebox_tpl *);
void	 cana_puk_tpl(struct ca_new_args *, const char *, struct ebox_tpl *);
void	 cana_dn(struct ca_new_args *, X509_NAME *);
void	 cana_scope(struct ca_new_args *, struct cert_var_scope *);

void	 cana_free(struct ca_new_args *);

errf_t		*ca_generate(const char *path, struct ca_new_args *args,
    struct piv_token *tkn, struct ca **outca);

errf_t		*ca_open(const char *path, struct ca **outca);

int		 ca_config_dirty(struct ca *ca);
errf_t		*ca_config_write(struct ca *ca, struct ca_session *sess);

uint		 ca_crl_uri_count(const struct ca *ca);
const char	*ca_crl_uri(const struct ca *ca, uint index);
errf_t		*ca_crl_uri_remove(struct ca *ca, const char *uri);
errf_t		*ca_crl_uri_add(struct ca *ca, const char *uri);

uint		 ca_ocsp_uri_count(const struct ca *ca);
const char	*ca_ocsp_uri(const struct ca *ca, uint index);
errf_t		*ca_ocsp_uri_remove(struct ca *ca, const char *uri);
errf_t		*ca_ocsp_uri_add(struct ca *ca, const char *uri);

uint		 ca_aia_uri_count(const struct ca *ca);
const char	*ca_aia_uri(const struct ca *ca, uint index);
errf_t		*ca_aia_uri_remove(struct ca *ca, const char *uri);
errf_t		*ca_aia_uri_add(struct ca *ca, const char *uri);

struct ebox	*ca_get_ebox(struct ca *ca, enum ca_ebox_type type);
const char	*ca_get_ebox_tpl(struct ca *ca, enum ca_ebox_type type);
errf_t		*ca_set_ebox_tpl(struct ca *ca, enum ca_ebox_type type,
    const char *tplname);
errf_t		*ca_rekey_ebox(struct ca *ca, enum ca_ebox_type type,
    struct ebox *unlocked);

struct ebox_tpl	*ca_get_ebox_tpl_name(struct ca *ca, const char *name);
errf_t		*ca_set_ebox_tpl_name(struct ca *ca, const char *name,
    struct ebox_tpl *tpl);

const char	*ca_slug(const struct ca *ca);
const char	*ca_guidhex(const struct ca *ca);
const struct sshkey	*ca_pubkey(const struct ca *ca);
const struct sshkey	*ca_cak(const struct ca *ca);
char		*ca_dn(const struct ca *ca);

errf_t		*ca_generate_crl(struct ca *ca, struct ca_session *sess,
    X509_CRL *crl);

typedef struct json_object json_object;
typedef void (*log_iter_cb_t)(json_object *entry, void *cookie);

errf_t 		*ca_log_verify(struct ca *ca, char **final_hash,
    log_iter_cb_t cb, void *cookie);

void		 ca_close(struct ca *ca);

errf_t		*ca_open_session(struct ca *ca, struct ca_session **outsess);
boolean_t	 ca_session_authed(struct ca_session *sess);
enum piv_pin	 ca_session_auth_type(struct ca_session *sess);
errf_t		*ca_session_auth(struct ca_session *sess, enum piv_pin type,
    const char *pin);
errf_t		*ca_rotate_pin(struct ca_session *sess);
void		 ca_close_session(struct ca_session *sess);

errf_t		*ca_revoke_cert(struct ca *ca, struct ca_session *sess,
    X509 *cert);
errf_t		*ca_revoke_cert_serial(struct ca *ca, struct ca_session *sess,
    BIGNUM *serial);

struct cert_var_scope	*ca_make_scope(struct ca *ca,
    struct cert_var_scope *parent);

struct ca_cert_tpl	*ca_cert_tpl_get(struct ca *ca, const char *name);
struct ca_cert_tpl	*ca_cert_tpl_first(struct ca *ca);
errf_t			*ca_cert_tpl_add(struct ca *ca, struct ca_cert_tpl *tpl);
errf_t			*ca_cert_tpl_remove(struct ca *ca, struct ca_cert_tpl *tpl);

struct ca_cert_tpl	*ca_cert_tpl_new(const char *name, const char *help,
    enum ca_cert_type type, enum ca_cert_tpl_flags flags,
    const struct cert_tpl *tpl, struct cert_var_scope *tplscope);
void			 ca_cert_tpl_free(struct ca_cert_tpl *tpl);
struct ca_cert_tpl	*ca_cert_tpl_next(struct ca_cert_tpl *tpl);
const char		*ca_cert_tpl_name(const struct ca_cert_tpl *tpl);
const char		*ca_cert_tpl_help(const struct ca_cert_tpl *tpl);
enum ca_cert_type	 ca_cert_tpl_type(const struct ca_cert_tpl *tpl);
enum ca_cert_tpl_flags	 ca_cert_tpl_flags(const struct ca_cert_tpl *tpl);
const struct cert_tpl	*ca_cert_tpl_tpl(const struct ca_cert_tpl *tpl);
struct cert_var_scope	*ca_cert_tpl_make_scope(struct ca_cert_tpl *tpl,
    struct cert_var_scope *parent);

struct ca_token_tpl	*ca_token_tpl_get(struct ca *ca, const char *name);
struct ca_token_tpl	*ca_token_tpl_first(struct ca *ca);
errf_t			*ca_token_tpl_add(struct ca *ca, struct ca_token_tpl *tpl);
errf_t			*ca_token_tpl_remove(struct ca *ca, struct ca_token_tpl *tpl);

struct ca_token_tpl	*ca_token_tpl_new(const char *name, const char *help,
    enum ca_token_tpl_flags flags, struct cert_var_scope *tplscope);
void			 ca_token_tpl_free(struct ca_token_tpl *tpl);
struct ca_token_tpl	*ca_token_tpl_next(struct ca_token_tpl *tpl);
const char		*ca_token_tpl_name(const struct ca_token_tpl *tpl);
const char		*ca_token_tpl_help(const struct ca_token_tpl *tpl);
const char		*ca_token_tpl_get_ebox_tpl(struct ca *ca,
    enum ca_ebox_type type);
errf_t			*ca_token_tpl_set_ebox_tpl(struct ca *ca,
    enum ca_ebox_type type, const char *tplname);
errf_t			*ca_set_ebox_tpl(struct ca *ca, enum ca_ebox_type type,
    const char *tplname);
enum ca_token_tpl_flags	 ca_token_tpl_flags(const struct ca_token_tpl *tpl);
struct cert_var_scope	*ca_token_tpl_make_scope(struct ca_token_tpl *tpl,
    struct cert_var_scope *parent);
/* todo: api for requiring attestation and setting attestation ca certs */

struct ca_token_slot_tpl	*ca_token_slot_tpl(struct ca_token_tpl *tpl,
    enum piv_slotid slot);
struct ca_token_slot_tpl	*ca_token_slot_tpl_first(
    struct ca_token_tpl *tpl);
errf_t				*ca_token_slot_tpl_add(
    struct ca_token_tpl *tkn, struct ca_token_slot_tpl *tpl);
errf_t				*ca_token_slot_tpl_remove(
    struct ca_token_tpl *tkn, struct ca_token_slot_tpl *tpl);

struct ca_token_slot_tpl	*ca_token_slot_tpl_new(enum piv_slotid slot,
    enum piv_alg alg, enum ykpiv_pin_policy pinpol,
    enum ykpiv_touch_policy tpol, struct ca_cert_tpl *ctpl);
void				 ca_token_slot_tpl_free(
    struct ca_token_slot_tpl *tpl);

struct ca_token_slot_tpl	*ca_token_slot_tpl_next(
    struct ca_token_slot_tpl *tpl);
enum piv_slotid			 ca_token_slot_tpl_id(
    const struct ca_token_slot_tpl *tpl);
struct ca_cert_tpl		*ca_token_slot_tpl_cert(
    struct ca_token_slot_tpl *tpl);
enum piv_alg			 ca_token_slot_tpl_alg(
    const struct ca_token_slot_tpl *tpl);
enum ykpiv_pin_policy		 ca_token_slot_tpl_pin_policy(
    struct ca_token_slot_tpl *tpl);
enum ykpiv_touch_policy		 ca_token_slot_tpl_touch_policy(
    struct ca_token_slot_tpl *tpl);
struct cert_var_scope		*ca_token_slot_tpl_make_scope(
    struct ca_token_slot_tpl *tpl, struct cert_var_scope *parent);

errf_t 	*ca_cert_sign(struct ca_session *sess, struct ca_cert_tpl *tpl,
    struct cert_var_scope *certscope, EVP_PKEY *pubkey, X509 *out);
errf_t	*ca_cert_sign_req(struct ca_session *sess, struct ca_cert_tpl *tpl,
    struct cert_var_scope *certscope, X509_REQ *req, X509 *out);

struct provision_args	*pva_new(void);
void	 pva_free(struct provision_args *);

void	 pva_token_scope(struct provision_args *, struct cert_var_scope *);
void	 pva_initial_pin(struct provision_args *, const char *);
void	 pva_initial_puk(struct provision_args *, const char *);
void	 pva_initial_admin_key(struct provision_args *, enum piv_alg,
    uint8_t *, size_t);
void	 pva_new_pin(struct provision_args *, const char *);
/* These might be ignored, depending on token_tpl flags */
void	 pva_new_puk(struct provision_args *, const char *);
void	 pva_new_admin_key(struct provision_args *, enum piv_alg,
    uint8_t *, size_t);

errf_t	*ca_token_provision(struct ca_session *sess, struct ca_token_tpl *tpl,
    struct piv_token *token, struct provision_args *args);

/*
 * Utility functions
 */

errf_t	*parse_dn(const char *dnstr, X509_NAME *name);
errf_t	*unparse_dn(X509_NAME *name, char **out);

#endif
