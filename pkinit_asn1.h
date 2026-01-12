/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2021, The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

#if !defined(_PKINIT_ASN1_H)
#define _PKINIT_ASN1_H

#include <stdint.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

extern const ASN1_ITEM PKINIT_PRINC_it;
extern const ASN1_ITEM PKINIT_PRINC_NAME_it;

typedef struct {
	ASN1_INTEGER *type;
	STACK_OF(ASN1_GENERALSTRING) *parts;
} PKINIT_PRINC_NAME;

typedef struct {
	ASN1_GENERALSTRING *realm;
	PKINIT_PRINC_NAME *name;
} PKINIT_PRINC;

enum PKINIT_PRINC_type {
	KRB5_NT_UNKNOWN		= 0,
	KRB5_NT_PRINCIPAL	= 1,
	KRB5_NT_SRV_INST	= 2,
	KRB5_NT_SRV_HST		= 3,
	KRB5_NT_SRV_XHST	= 4,
	KRB5_NT_UID		= 5,
	KRB5_NT_X500_PRINCIPAL	= 6,
	KRB5_NT_SMTP_NAME	= 7,
	KRB5_NT_ENTERPRISE	= 10
};

PKINIT_PRINC *PKINIT_PRINC_new(void);
PKINIT_PRINC_NAME *PKINIT_PRINC_NAME_new(void);
void PKINIT_PRINC_free(PKINIT_PRINC *);
void PKINIT_PRINC_NAME_free(PKINIT_PRINC_NAME *);

int PKINIT_PRINC_set_realm(PKINIT_PRINC *, const char *);
int PKINIT_PRINC_set_name(PKINIT_PRINC *, PKINIT_PRINC_NAME *);

int PKINIT_PRINC_NAME_set(PKINIT_PRINC_NAME *, enum PKINIT_PRINC_type,
    /*const char *part0,*/...);

int i2d_PKINIT_PRINC(PKINIT_PRINC *, unsigned char **);
PKINIT_PRINC *d2i_PKINIT_PRINC(PKINIT_PRINC **, const unsigned char **, long);
ASN1_STRING *pack_PKINIT_PRINC(PKINIT_PRINC *, ASN1_STRING **);

PKINIT_PRINC *v2i_PKINIT_PRINC(PKINIT_PRINC **, const char *);
char *i2v_PKINIT_PRINC(PKINIT_PRINC *princ);

#endif
