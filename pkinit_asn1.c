/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2021, The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "debug.h"

#include "pkinit_asn1.h"

static const ASN1_TEMPLATE PKINIT_PRINC_NAME_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(PKINIT_PRINC_NAME, type),
		.field_name = "type",
		.item = &ASN1_INTEGER_it
	},
	{
		.flags = ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF,
		.tag = 1,
		.offset = offsetof(PKINIT_PRINC_NAME, parts),
		.field_name = "parts",
		.item = &ASN1_GENERALSTRING_it
	}
};

const ASN1_ITEM PKINIT_PRINC_NAME_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = PKINIT_PRINC_NAME_seq_tt,
	.tcount = sizeof(PKINIT_PRINC_NAME_seq_tt) / sizeof(ASN1_TEMPLATE),
	.size = sizeof(PKINIT_PRINC_NAME),
	.sname = "PKINIT_PRINC_NAME"
};

static const ASN1_TEMPLATE PKINIT_PRINC_seq_tt[] = {
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 0,
		.offset = offsetof(PKINIT_PRINC, realm),
		.field_name = "realm",
		.item = &ASN1_GENERALSTRING_it
	},
	{
		.flags = ASN1_TFLG_EXPLICIT,
		.tag = 1,
		.offset = offsetof(PKINIT_PRINC, name),
		.field_name = "name",
		.item = &PKINIT_PRINC_NAME_it
	}
};

const ASN1_ITEM PKINIT_PRINC_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = PKINIT_PRINC_seq_tt,
	.tcount = sizeof(PKINIT_PRINC_seq_tt) / sizeof(ASN1_TEMPLATE),
	.size = sizeof(PKINIT_PRINC),
	.sname = "PKINIT_PRINC"
};

PKINIT_PRINC *
PKINIT_PRINC_new(void)
{
	return (PKINIT_PRINC *)ASN1_item_new(&PKINIT_PRINC_it);
}

PKINIT_PRINC_NAME *
PKINIT_PRINC_NAME_new(void)
{
	return (PKINIT_PRINC_NAME *)ASN1_item_new(&PKINIT_PRINC_NAME_it);
}

void
PKINIT_PRINC_free(PKINIT_PRINC *princ)
{
	ASN1_item_free((ASN1_VALUE *)princ, &PKINIT_PRINC_it);
}

void
PKINIT_PRINC_NAME_free(PKINIT_PRINC_NAME *name)
{
	ASN1_item_free((ASN1_VALUE *)name, &PKINIT_PRINC_NAME_it);
}

int
PKINIT_PRINC_set_realm(PKINIT_PRINC *princ, const char *realm)
{
	ASN1_GENERALSTRING *str;
	str = ASN1_GENERALSTRING_new();
	if (str == NULL)
		return (0);
	if (ASN1_STRING_set(str, realm, strlen(realm)) != 1)
		return (0);
	if (princ->realm != NULL)
		ASN1_GENERALSTRING_free(princ->realm);
	princ->realm = str;
	return (1);
}

int
PKINIT_PRINC_set_name(PKINIT_PRINC *princ, PKINIT_PRINC_NAME *name)
{
	if (princ->name != NULL)
		ASN1_item_free((ASN1_VALUE *)princ->name, &PKINIT_PRINC_NAME_it);
	princ->name = name;
	return (1);
}

int
PKINIT_PRINC_NAME_set(PKINIT_PRINC_NAME *name, enum PKINIT_PRINC_type type, ...)
{
	va_list ap;
	const char *arg;

	if (name->type == NULL)
		name->type = ASN1_INTEGER_new();
	if (name->type == NULL)
		return (0);
	if (ASN1_INTEGER_set(name->type, type) != 1)
		return (0);

	if (name->parts != NULL) {
		sk_ASN1_GENERALSTRING_pop_free(name->parts,
		    ASN1_GENERALSTRING_free);
	}
	name->parts = sk_ASN1_GENERALSTRING_new_null();
	if (name->parts == NULL)
		return (0);

	va_start(ap, type);
	while ((arg = va_arg(ap, const char *)) != NULL) {
		ASN1_GENERALSTRING *gs;
		gs = ASN1_GENERALSTRING_new();
		if (gs == NULL)
			return (0);
		if (ASN1_STRING_set(gs, arg, strlen(arg)) != 1)
			return (0);
		if (sk_ASN1_GENERALSTRING_push(name->parts, gs) == 0)
			return (0);
	}
	va_end(ap);

	return (1);
}

int
i2d_PKINIT_PRINC(PKINIT_PRINC *princ, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)princ, out, &PKINIT_PRINC_it);
}

ASN1_STRING *
pack_PKINIT_PRINC(PKINIT_PRINC *princ, ASN1_STRING **out)
{
	return ASN1_item_pack(princ, &PKINIT_PRINC_it, out);
}

PKINIT_PRINC *
d2i_PKINIT_PRINC(PKINIT_PRINC **out, const unsigned char **in, long len)
{
	return (PKINIT_PRINC *)ASN1_item_d2i((ASN1_VALUE **)out, in, len,
	    &PKINIT_PRINC_it);
}

char *
i2v_PKINIT_PRINC(PKINIT_PRINC *princ)
{
	char *out;
	char *p;
	PKINIT_PRINC_NAME *n;
	ASN1_GENERALSTRING *gs;
	STACK_OF(ASN1_GENERALSTRING) *gss;
	int len;
	size_t outlen = 1024;

	out = malloc(outlen);
	if (out == NULL)
		return (NULL);
	out[0] = '\0';

	gss = sk_ASN1_GENERALSTRING_new_null();
	if (gss == NULL)
		return (NULL);

	n = princ->name;
	while ((gs = sk_ASN1_GENERALSTRING_shift(n->parts)) != NULL) {
		len = ASN1_STRING_length(gs);
		p = malloc(len + 1);
		bcopy(ASN1_STRING_get0_data(gs), p, len);
		p[len] = '\0';
		if (*out != '\0')
			xstrlcat(out, "/", outlen);
		xstrlcat(out, p, outlen);
		free(p);
		sk_ASN1_GENERALSTRING_push(gss, gs);
	}
	sk_ASN1_GENERALSTRING_free(n->parts);
	n->parts = gss;

	len = ASN1_STRING_length(princ->realm);
	p = malloc(len + 1);
	bcopy(ASN1_STRING_get0_data(princ->realm), p, len);
	p[len] = '\0';
	xstrlcat(out, "@", outlen);
	xstrlcat(out, p, outlen);
	free(p);

	return (out);
}

PKINIT_PRINC *
v2i_PKINIT_PRINC(PKINIT_PRINC **out, const char *inp)
{
	char *inpm, *saveptr = NULL, *token, *realm, *nmpart;
	PKINIT_PRINC_NAME *name = NULL;
	PKINIT_PRINC *princ = NULL;

	inpm = strdup(inp);
	if (inpm == NULL)
		return (NULL);

	princ = PKINIT_PRINC_new();
	if (princ == NULL)
		goto bad;

	nmpart = strtok_r(inpm, "@", &saveptr);
	if (nmpart == NULL)
		goto bad;
	realm = strtok_r(NULL, "@", &saveptr);
	if (realm == NULL)
		goto bad;
	if (PKINIT_PRINC_set_realm(princ, realm) != 1)
		goto bad;

	name = PKINIT_PRINC_NAME_new();
	if (name == NULL)
		goto bad;

	name->type = ASN1_INTEGER_new();
	if (name->type == NULL)
		goto bad;
	if (ASN1_INTEGER_set(name->type, KRB5_NT_PRINCIPAL) != 1)
		goto bad;

	name->parts = sk_ASN1_GENERALSTRING_new_null();
	if (name->parts == NULL)
		goto bad;

	saveptr = NULL;
	token = strtok_r(nmpart, "/", &saveptr);
	while (token != NULL) {
		ASN1_GENERALSTRING *gs;
		gs = ASN1_GENERALSTRING_new();
		if (gs == NULL)
			goto bad;
		if (ASN1_STRING_set(gs, token, strlen(token)) != 1)
			goto bad;
		if (sk_ASN1_GENERALSTRING_push(name->parts, gs) == 0)
			goto bad;
		token = strtok_r(NULL, "/", &saveptr);
	}

	if (PKINIT_PRINC_set_name(princ, name) != 1)
		goto bad;
	name = NULL;

	goto out;

bad:
	if (princ != NULL)
		PKINIT_PRINC_free(princ);

out:
	free(inpm);
	if (name != NULL)
		PKINIT_PRINC_NAME_free(name);
	if (out != NULL)
		*out = princ;
	return (princ);
}
