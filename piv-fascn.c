/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 * Copyright 2024 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

/*
 * Documentation references used below:
 * [piv]: https://csrc.nist.gov/publications/detail/sp/800-73/4/final
 * [yubico-piv]: https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
 * [iso7816]: (you'll need an ISO membership, or try a university library)
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

#include "debug.h"

#include "openssh/config.h"
#include "openssh/ssherr.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/cipher.h"
#include "openssh/authfd.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"

/* Contains structs apdubuf, piv_ecdh_box, and enum piv_box_version */
#include "piv-internal.h"

void
piv_fascn_free(struct piv_fascn *pf)
{
	if (pf == NULL)
		return;
	free(pf->pf_agency);
	free(pf->pf_system);
	free(pf->pf_crednum);
	free(pf->pf_cs);
	free(pf->pf_ici);
	free(pf->pf_pi);
	free(pf->pf_oi);
	strbuf_free(pf->pf_str_cache);
	free(pf);
}

static inline errf_t *
read_bcd_char(struct bcdbuf *b, const char *name, enum iso7811_bcd *pchar,
    const char **pstr)
{
	errf_t *e;
	enum iso7811_bcd bchar;
	e = bcdbuf_read(b, &bchar);
	if (e != ERRF_OK)
		return (errf("FASCNFormatError", e, "failed to read %s", name));
	*pchar = bchar;
	if (pstr != NULL)
		*pstr = iso7811_to_str(bchar);
	return (ERRF_OK);
}

static inline errf_t *
read_bcd_field(struct bcdbuf *b, size_t limit, const char *name, char **pstr,
    enum iso7811_bcd *pterm)
{
	errf_t *e;
	e = bcdbuf_read_string(b, limit, pstr, pterm);
	if (e != ERRF_OK) {
		return (errf("FASCNFormatError", e, "failed to read field %s",
		    name));
	}
	return (ERRF_OK);
}

/*
 * See TIG SCEPACS for details here
 */
errf_t *
piv_fascn_decode(const uint8_t *data, size_t len, struct piv_fascn **out)
{
	struct piv_fascn *pf;
	errf_t *err = NULL;
	enum iso7811_bcd v = ISO_BCD_NONE, term = ISO_BCD_NONE;
	const char *vstr = NULL;
	char *oc = NULL, *poa = NULL;
	struct bcdbuf *b = NULL;
	uint i;

	/* First check for all-zero value, give this special treatment. */
	for (i = 0; i < len; ++i) {
		if (data[i] != 0x00)
			break;
	}
	if (i == len && len >= 7 && len <= 25) {
		pf = piv_fascn_zero();
		if (pf == NULL)
			return (ERRF_NOMEM);
		pf->pf_flags |= PIV_FASCN_ALL_ZERO;
		goto good;
	}

	pf = calloc(1, sizeof(struct piv_fascn));
	if (pf == NULL)
		return (ERRF_NOMEM);

	pf->pf_str_cache = strbuf_new();
	if (pf->pf_str_cache == NULL) {
		free(pf);
		return (ERRF_NOMEM);
	}

	b = bcdbuf_from(data, len);
	__CPROVER_assume(b != NULL);
	VERIFY(b != NULL);

	if ((err = read_bcd_char(b, "start sentinel", &v, &vstr)))
		goto out;
	if (v != ISO_BCD_SS) {
		err = errf("FASCNFormatError", NULL, "Read 0x%x ('%s'), "
		    "expected start sentinel", v, vstr == NULL ? "?" : vstr);
		goto out;
	}

	if ((err = read_bcd_field(b, 5, "agency code", &pf->pf_agency, NULL)) ||
	    (err = read_bcd_field(b, 5, "system code", &pf->pf_system, NULL)) ||
	    (err = read_bcd_field(b, 7, "cred num", &pf->pf_crednum, NULL)) ||
	    (err = read_bcd_field(b, 2, "cs", &pf->pf_cs, NULL)) ||
	    (err = read_bcd_field(b, 2, "ici", &pf->pf_ici, NULL)) ||
	    (err = read_bcd_field(b, 10, "pi", &pf->pf_pi, NULL)) ||
	    (err = read_bcd_field(b, 1, "oc", &oc, NULL)) ||
	    (err = read_bcd_field(b, 4, "oi", &pf->pf_oi, NULL)) ||
	    (err = read_bcd_field(b, 2, "poa", &poa, &term))) {
		goto out;
	}

	switch (oc[0]) {
	case '1':
		pf->pf_oc = PIV_FASCN_OC_FEDERAL;
		break;
	case '2':
		pf->pf_oc = PIV_FASCN_OC_STATE;
		break;
	case '3':
		pf->pf_oc = PIV_FASCN_OC_COMMERCIAL;
		break;
	case '4':
		pf->pf_oc = PIV_FASCN_OC_FOREIGN;
		break;
	default:
		err = errf("FASCNFormatError", NULL, "Unknown OC value: '%s'",
		    oc);
		goto out;
	}

	switch (poa[0]) {
	case '1':
		pf->pf_poa = PIV_FASCN_POA_EMPLOYEE;
		break;
	case '2':
		pf->pf_poa = PIV_FASCN_POA_CIVIL;
		break;
	case '3':
		pf->pf_poa = PIV_FASCN_POA_EXECUTIVE;
		break;
	case '4':
		pf->pf_poa = PIV_FASCN_POA_UNIFORMED;
		break;
	case '5':
		pf->pf_poa = PIV_FASCN_POA_CONTRACTOR;
		break;
	case '6':
		pf->pf_poa = PIV_FASCN_POA_AFFILIATE;
		break;
	case '7':
		pf->pf_poa = PIV_FASCN_POA_BENEFICIARY;
		break;
	default:
		err = errf("FASCNFormatError", NULL, "Unknown POA value: '%s'",
		    poa);
		goto out;
	}

	if (term != ISO_BCD_ES) {
		vstr = iso7811_to_str(term);
		err = errf("FASCNFormatError", NULL, "Read 0x%x ('%s'), "
		    "expected end sentinel", term, vstr == NULL ? "?" : vstr);
		goto out;
	}

	if ((err = bcdbuf_read_and_check_lrc(b)))
		goto out;

	if (!bcdbuf_at_end(b)) {
		err = errf("FASCNFormatError", NULL, "FASC-N contains "
		    "trailing bytes after end sentinel");
		goto out;
	}

good:
	*out = pf;
	pf = NULL;
	err = ERRF_OK;

out:
	piv_fascn_free(pf);
	bcdbuf_free(b);
	free(oc);
	free(poa);
	return (err);
}

const char *
piv_fascn_get_agency_code(const struct piv_fascn *pf)
{
	return (pf->pf_agency);
}

const char *
piv_fascn_get_system_code(const struct piv_fascn *pf)
{
	return (pf->pf_system);
}

const char *
piv_fascn_get_cred_number(const struct piv_fascn *pf)
{
	return (pf->pf_crednum);
}

const char *
piv_fascn_get_cred_series(const struct piv_fascn *pf)
{
	return (pf->pf_cs);
}

const char *
piv_fascn_get_indiv_cred_issue(const struct piv_fascn *pf)
{
	return (pf->pf_ici);
}

const char *
piv_fascn_get_person_id(const struct piv_fascn *pf)
{
	return (pf->pf_pi);
}

const char *
piv_fascn_get_org_id(const struct piv_fascn *pf)
{
	return (pf->pf_oi);
}

enum piv_fascn_oc
piv_fascn_get_org_type(const struct piv_fascn *pf)
{
	return (pf->pf_oc);
}

enum piv_fascn_poa
piv_fascn_get_assoc(const struct piv_fascn *pf)
{
	return (pf->pf_poa);
}

const char *
piv_fascn_org_type_to_string(enum piv_fascn_oc oc)
{
	switch (oc) {
	case PIV_FASCN_OC_FEDERAL:
		return ("federal");
	case PIV_FASCN_OC_STATE:
		return ("state");
	case PIV_FASCN_OC_COMMERCIAL:
		return ("commercial");
	case PIV_FASCN_OC_FOREIGN:
		return ("foreign");
	default:
		VERIFY(0);
		return (NULL);
	}
}

const char *
piv_fascn_assoc_to_string(enum piv_fascn_poa poa)
{
	switch (poa) {
	case PIV_FASCN_POA_EMPLOYEE:
		return ("employee");
	case PIV_FASCN_POA_CIVIL:
		return ("civil");
	case PIV_FASCN_POA_EXECUTIVE:
		return ("executive-staff");
	case PIV_FASCN_POA_UNIFORMED:
		return ("uniformed-service");
	case PIV_FASCN_POA_CONTRACTOR:
		return ("contractor");
	case PIV_FASCN_POA_AFFILIATE:
		return ("affiliate");
	case PIV_FASCN_POA_BENEFICIARY:
		return ("beneficiary");
	default:
		VERIFY(0);
		return (NULL);
	}
}

const char *
piv_fascn_to_string(const struct piv_fascn *pf)
{
	struct strbuf *sb;

	if (strbuf_len(pf->pf_str_cache) > 0)
		return (strbuf_cstr(pf->pf_str_cache));

	sb = pf->pf_str_cache;

	strbuf_append(sb, pf->pf_agency);
	strbuf_append(sb, "-");
	/*
	 * leave the rest of the fields off in CBMC, this is enough to prove
	 * our approach is safe.
	 */
#if !defined(__CPROVER)
	strbuf_append(sb, pf->pf_system);
	strbuf_append(sb, "-");
	strbuf_append(sb, pf->pf_crednum);
	strbuf_append(sb,  "-");
	strbuf_append(sb, pf->pf_cs);
	strbuf_append(sb, "-");
	strbuf_append(sb, pf->pf_ici);
	strbuf_append(sb, "/");
	strbuf_append(sb, piv_fascn_org_type_to_string(pf->pf_oc));
	strbuf_append(sb, ":");
	strbuf_append(sb, pf->pf_oi);
	strbuf_append(sb, "/");
	strbuf_append(sb, piv_fascn_assoc_to_string(pf->pf_poa));
	strbuf_append(sb, ":");
	strbuf_append(sb, pf->pf_pi);
#endif

	return (strbuf_cstr(sb));
}

inline static char *
strpaddup(const char *instr, size_t len, char prefix)
{
	char *out;
	size_t i, pad;
	if (instr == NULL)
		return (NULL);
	out = malloc(len + 1);
	__CPROVER_assume(out != NULL);
	VERIFY(out != NULL);
	VERIFY(strlen(instr) <= len);
	pad = len - strlen(instr);
	for (i = 0; i < pad; ++i)
		out[i] = prefix;
	out[pad] = '\0';
	xstrlcat(out, instr, len + 1);
	return (out);
}

void
piv_fascn_set_agency_code(struct piv_fascn *pf, const char *v)
{
	free(pf->pf_agency);
	pf->pf_agency = strpaddup(v, 4, '0');
	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

void
piv_fascn_set_system_code(struct piv_fascn *pf, const char *v)
{
	free(pf->pf_system);
	pf->pf_system = strpaddup(v, 4, '0');
	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

void
piv_fascn_set_cred_number(struct piv_fascn *pf, const char *v)
{
	free(pf->pf_crednum);
	pf->pf_crednum = strpaddup(v, 6, '0');
	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

void
piv_fascn_set_cred_series(struct piv_fascn *pf, const char *v)
{
	free(pf->pf_cs);
	pf->pf_cs = strpaddup(v, 1, '0');
	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

void
piv_fascn_set_indiv_cred_issue(struct piv_fascn *pf, const char *v)
{
	free(pf->pf_ici);
	pf->pf_ici = strpaddup(v, 1, '0');
	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

void
piv_fascn_set_person_id(struct piv_fascn *pf, enum piv_fascn_poa poa,
    const char *v)
{
	pf->pf_poa = poa;
	free(pf->pf_pi);
	pf->pf_pi = strpaddup(v, 10, '0');

	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

void
piv_fascn_set_org_id(struct piv_fascn *pf, enum piv_fascn_oc oc, const char *v)
{
	pf->pf_oc = oc;
	free(pf->pf_oi);
	pf->pf_oi = strpaddup(v, 4, '0');

	strbuf_reset(pf->pf_str_cache);
	pf->pf_flags &= ~PIV_FASCN_ALL_ZERO;
}

struct piv_fascn *
piv_fascn_clone(const struct piv_fascn *opf)
{
	struct piv_fascn *pf;

	pf = calloc(1, sizeof (struct piv_fascn));
	if (pf == NULL)
		return (NULL);

	pf->pf_agency = nstrdup(opf->pf_agency);
	pf->pf_system = nstrdup(opf->pf_system);
	pf->pf_crednum = nstrdup(opf->pf_crednum);
	pf->pf_cs = nstrdup(opf->pf_cs);
	pf->pf_ici = nstrdup(opf->pf_ici);
	pf->pf_pi = nstrdup(opf->pf_pi);
	pf->pf_oi = nstrdup(opf->pf_oi);
	pf->pf_str_cache = strbuf_new();
	strbuf_concat(pf->pf_str_cache, opf->pf_str_cache);

	pf->pf_oc = opf->pf_oc;
	pf->pf_poa = opf->pf_poa;
	pf->pf_flags = opf->pf_flags;

	return (pf);
}

struct piv_fascn *
piv_fascn_zero(void)
{
	struct piv_fascn *pf;

	pf = calloc(1, sizeof (struct piv_fascn));
	if (pf == NULL)
		return (NULL);

	pf->pf_str_cache = strbuf_new();
	if (pf->pf_str_cache == NULL) {
		free(pf);
		return (NULL);
	}

	pf->pf_agency = nstrdup("0000");
	pf->pf_system = nstrdup("0000");
	pf->pf_crednum = nstrdup("000000");
	pf->pf_cs = nstrdup("0");
	pf->pf_ici = nstrdup("1");
	pf->pf_poa = PIV_FASCN_POA_EMPLOYEE;
	pf->pf_pi = nstrdup("0000000000");
	pf->pf_oc = PIV_FASCN_OC_COMMERCIAL;
	pf->pf_oi = nstrdup("0000");

	return (pf);
}

static inline errf_t *
write_bcd_char(struct bcdbuf *b, enum iso7811_bcd pchar, const char *name)
{
	errf_t *e;
	e = bcdbuf_write(b, pchar);
	if (e != ERRF_OK)
		return (errf("FASCNFormatError", e, "failed to write %s", name));
	return (ERRF_OK);
}

static inline errf_t *
write_bcd_field(struct bcdbuf *b, size_t limit, enum iso7811_bcd terminator,
    const char *name, const char *str)
{
	errf_t *e;
	if (strlen(str) > limit) {
		return (errf("FASCNFormatError", NULL, "value for field %s "
		    "is too long (max %zu digits)", name, limit));
	}
	e = bcdbuf_write_string(b, str, terminator);
	if (e != ERRF_OK) {
		return (errf("FASCNFormatError", e, "failed to write field %s",
		    name));
	}
	return (ERRF_OK);
}

errf_t *
piv_fascn_encode(const struct piv_fascn *pf, uint8_t **out, size_t *outlen)
{
	struct bcdbuf *b = NULL;
	errf_t *err;
	char oc[2] = {0}, poa[2] = {0};

	if (pf->pf_flags & PIV_FASCN_ALL_ZERO) {
		*out = calloc(1, 25);
		if (*out == NULL)
			return (ERRF_NOMEM);
		*outlen = 25;
		return (ERRF_OK);
	}

	b = bcdbuf_new();
	__CPROVER_assume(b != NULL);
	VERIFY(b != NULL);

	switch (pf->pf_oc) {
	case PIV_FASCN_OC_FEDERAL:
		oc[0] = '1';
		break;
	case PIV_FASCN_OC_STATE:
		oc[0] = '2';
		break;
	case PIV_FASCN_OC_COMMERCIAL:
		oc[0] = '3';
		break;
	case PIV_FASCN_OC_FOREIGN:
		oc[0] = '4';
		break;
	}

	switch (pf->pf_poa) {
	case PIV_FASCN_POA_EMPLOYEE:
		poa[0] = '1';
		break;
	case PIV_FASCN_POA_CIVIL:
		poa[0] = '2';
		break;
	case PIV_FASCN_POA_EXECUTIVE:
		poa[0] = '3';
		break;
	case PIV_FASCN_POA_UNIFORMED:
		poa[0] = '4';
		break;
	case PIV_FASCN_POA_CONTRACTOR:
		poa[0] = '5';
		break;
	case PIV_FASCN_POA_AFFILIATE:
		poa[0] = '6';
		break;
	case PIV_FASCN_POA_BENEFICIARY:
		poa[0] = '7';
		break;
	}

	if ((err = write_bcd_char(b, ISO_BCD_SS, "start sentinel")))
		goto out;

	err = write_bcd_field(b, 4, ISO_BCD_FS, "agency code", pf->pf_agency);
	if (err != ERRF_OK)
		goto out;

	err = write_bcd_field(b, 4, ISO_BCD_FS, "system code", pf->pf_system);
	if (err != ERRF_OK)
		goto out;

	err = write_bcd_field(b, 6, ISO_BCD_FS, "cred num", pf->pf_crednum);
	if (err != ERRF_OK)
		goto out;

	err = write_bcd_field(b, 1, ISO_BCD_FS, "CS", pf->pf_cs);
	if (err != ERRF_OK)
		goto out;

	err = write_bcd_field(b, 1, ISO_BCD_FS, "ICI", pf->pf_ici);
	if (err != ERRF_OK)
		goto out;

	err = write_bcd_field(b, 10, 0, "person id", pf->pf_pi);
	if (err != ERRF_OK)
		goto out;
	err = write_bcd_field(b, 1, 0, "org category", oc);
	if (err != ERRF_OK)
		goto out;
	err = write_bcd_field(b, 4, 0, "org id", pf->pf_oi);
	if (err != ERRF_OK)
		goto out;
	err = write_bcd_field(b, 1, ISO_BCD_ES, "POA", poa);
	if (err != ERRF_OK)
		goto out;

	err = bcdbuf_write_lrc(b);
	if (err != ERRF_OK)
		goto out;

	*out = bcdbuf_to_bytes(b, outlen);

out:
	bcdbuf_free(b);
	return (err);
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_piv_fascn_c
uint8_t nondet_u8(void);

uint8_t *
genbinstr(size_t minlen, size_t maxlen, size_t *plen)
{
	size_t len, i;
	uint8_t *buf;
	__CPROVER_assume(len >= minlen);
	__CPROVER_assume(len <= maxlen);
	buf = malloc(len);
	__CPROVER_assume(buf != NULL);
	for (i = 0; i < len; ++i) {
		uint8_t c;
		buf[i] = c;
	}
	*plen = len;
	return (buf);
}

char *
gennumstr(size_t minlen, size_t maxlen)
{
	size_t len, i;
	char *buf;
	__CPROVER_assume(len >= minlen);
	__CPROVER_assume(len <= maxlen);
	buf = malloc(len + 1);
	__CPROVER_assume(buf != NULL);
	for (i = 0; i < len; ++i) {
		char c;
		__CPROVER_assume(c >= '0' && c <= '9');
		buf[i] = c;
	}
	buf[len] = '\0';
	return (buf);
}

void
fascn_write_proof(void)
{
	struct piv_fascn *fascn;
	errf_t *err;
	uint8_t *buf;
	size_t len, i;
	const char *str;
	char *agency;

	__CPROVER_assume(ERRF_NOMEM != NULL);

	/* Verify we can construct a zero FASC-N and modify it */
	fascn = piv_fascn_zero();
	__CPROVER_assume(fascn != NULL);

	err = piv_fascn_encode(fascn, &buf, &len);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(buf != NULL);
	assert(len == 25);
	free(buf);

	str = piv_fascn_to_string(fascn);
	assert(str != NULL);
	assert(strncmp(str, "0000-", 5) == 0);

	agency = gennumstr(4, 4);
	__CPROVER_assume(agency[0] != '0');
	piv_fascn_set_agency_code(fascn, agency);

	/* The string repr should change */
	str = piv_fascn_to_string(fascn);
	assert(str != NULL);
	assert(strncmp(str, agency, 4) == 0);
	assert(str[4] == '-');

	err = piv_fascn_encode(fascn, &buf, &len);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(buf != NULL);
	assert(len == 25);

	piv_fascn_free(fascn);
	free(buf);
}

void
fascn_read_proof(void)
{
	struct piv_fascn *fascn;
	errf_t *err;
	uint8_t *buf, *nbuf;
	size_t len, i;
	const char *str;

	/*
	 * All inputs shorter than 7 bytes (56 bits) cannot be parsed as a
	 * FASC-N (not enough bits for the required number of field terminators)
	 */
	uint8_t *buf0 = genbinstr(0, 6, &len);
	err = piv_fascn_decode(buf0, len, &fascn);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err != ERRF_OK);

	/*
	 * Inputs 7 - 25 bytes long may be valid FASC-Ns if they have enough
	 * terminators and their LRC is correct.
	 */
	uint8_t *buf1 = genbinstr(7, 25, &len);
	err = piv_fascn_decode(buf1, len, &fascn);
	__CPROVER_assume(err != ERRF_NOMEM);
	if (err == ERRF_OK) {
		assert(fascn != NULL);
		str = piv_fascn_get_agency_code(fascn);
		assert(str != NULL);
		assert(str[0] == '\0' || (str[0] >= '0' && str[0] <= '9'));

		str = piv_fascn_to_string(fascn);
		assert(str != NULL);
		assert(strlen(str) > 0);

		piv_fascn_free(fascn);
	}

	/*
	 * No inputs >25 bytes may be valid FASC-Ns. We'll stop the proof
	 * before 30, since that's our unwind limit.
	 */
	uint8_t *buf2 = genbinstr(26, 27, &len);
	err = piv_fascn_decode(buf2, len, &fascn);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err != ERRF_OK);
}

int
main(int argc, char *argv[])
{
	fascn_write_proof();
	fascn_read_proof();
	return (0);
}
#endif
