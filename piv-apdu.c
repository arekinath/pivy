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
#include <limits.h>

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

/* Tags used in the response to select on the PIV applet. */
enum piv_sel_tag {
	PIV_TAG_APT = 0x61,
	PIV_TAG_AID = 0x4F,
	PIV_TAG_AUTHORITY = 0x79,
	PIV_TAG_APP_LABEL = 0x50,
	PIV_TAG_URI = 0x5F50,
	PIV_TAG_ALGS = 0xAC,
	ISO_TAG_XLEN = 0x7F66,
};

errf_t *
piv_decode_rts(struct piv_rts *rts, const struct apdubuf *buf)
{
	errf_t *rv;
	struct tlv_state *tlv = NULL;
	uint tag, idx, uval;
	boolean_t extra_apt = B_FALSE;

	/*
	 * The PIV response to select is documented in
	 * [piv] 800-73-4 part 2, section 3.1.1
	 * In particular, table 3 has the list of tags here.
	 */
	tlv = tlv_init(buf->b_data, buf->b_offset, buf->b_len);

	if ((rv = tlv_read_tag(tlv, &tag)))
		goto out;
	if (tag != PIV_TAG_APT) {
		rv = tagerrf("INS_SELECT", tag);
		goto out;
	}

	/*
	 * Some buggy cards send a second nested APT tag inside the outer
	 * one. Check to see if that's the case before looping for the APT
	 * fields.
	 */
	if ((rv = tlv_peek_tag(tlv, &tag)))
		goto out;
	if (tag == PIV_TAG_APT) {
		extra_apt = B_TRUE;
		if ((rv = tlv_read_tag(tlv, &tag)))
			goto out;
		__CPROVER_assume(tag == PIV_TAG_APT);
		VERIFY(tag == PIV_TAG_APT);
	}

	while (!tlv_at_end(tlv)) {
		if ((rv = tlv_read_tag(tlv, &tag)))
			goto out;
		switch (tag) {
		case PIV_TAG_AID:
		case PIV_TAG_AUTHORITY:
			/* TODO: validate/store these maybe? */
			tlv_skip(tlv);
			break;
		case PIV_TAG_APP_LABEL:
			rv = tlv_read_string(tlv, &rts->pr_app_label);
			if (rv != NULL)
				goto out;
			if ((rv = tlv_end(tlv)))
				goto out;
			break;
		case PIV_TAG_URI:
			rv = tlv_read_string(tlv, &rts->pr_app_uri);
			if (rv != NULL)
				goto out;
			if ((rv = tlv_end(tlv)))
				goto out;
			break;
		case PIV_TAG_ALGS:
			while (!tlv_at_end(tlv)) {
				if ((rv = tlv_read_tag(tlv, &tag)))
					goto out;
				if (tag == 0x80) {
					idx = rts->pr_alg_count++;
					if (idx >= PIV_RTS_MAX_ALGS) {
						rv = errf("LengthError", NULL,
						    "too many algs");
						goto out;
					}
					rv = tlv_read_u8to32(tlv, &uval);
					if (rv)
						goto out;
					rts->pr_algs[idx] = uval;
					if ((rv = tlv_end(tlv)))
						goto out;
				} else if (tag == 0x06) {
					tlv_skip(tlv);
				} else {
					rv = tagerrf("algo "
					    "list in INS_SELECT",
					    tag);
					goto out;
				}
			}
			if ((rv = tlv_end(tlv)))
				goto out;
			break;
		default:
			rv = tagerrf("INS_SELECT", tag);
			goto out;
		}
	}

	if (extra_apt) {
		if ((rv = tlv_end(tlv)))
			goto out;
	}

	if ((rv = tlv_end(tlv)))
		goto out;

	while (!tlv_at_end(tlv)) {
		if ((rv = tlv_read_tag(tlv, &tag)))
			goto out;
		switch (tag) {
		case ISO_TAG_XLEN:
			if ((rv = tlv_read_tag(tlv, &tag)))
				goto out;
			if (tag != 0x02) {
				rv = tagerrf("INS_SELECT", tag);
				goto out;
			}
			rv = tlv_read_u8to32(tlv, &uval);
			if (rv)
				goto out;
			if ((rv = tlv_end(tlv)))
				goto out;
			rts->pr_max_cmd_apdu = uval;

			if ((rv = tlv_read_tag(tlv, &tag)))
				goto out;
			if (tag != 0x02) {
				rv = tagerrf("INS_SELECT", tag);
				goto out;
			}
			rv = tlv_read_u8to32(tlv, &uval);
			if (rv)
				goto out;
			if ((rv = tlv_end(tlv)))
				goto out;
			rts->pr_max_resp_apdu = uval;

			if ((rv = tlv_end(tlv)))
				goto out;

			rts->pr_has_xlen_info = B_TRUE;
			break;
		default:
			rv = tagerrf("INS_SELECT", tag);
			goto out;
		}
	}

	if (!tlv_at_root_end(tlv)) {
		rv = errf("LengthError", NULL, "PIV RTS response data "
		    "contains trailing garbage after APT");
		goto out;
	}

	tlv_free(tlv);
	return (ERRF_OK);

out:
	tlv_abort(tlv);
	return (rv);
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_piv_apdu_c

struct apdubuf *
genapdubuf(size_t minlen, size_t maxlen)
{
	size_t len, off;
	struct apdubuf *buf;
	__CPROVER_assume(len >= minlen);
	__CPROVER_assume(len <= maxlen);
	__CPROVER_assume(off >= 0);
	__CPROVER_assume(off < len);
	buf = malloc(sizeof (struct apdubuf));
	__CPROVER_assume(buf != NULL);
	buf->b_data = malloc(len + off);
	__CPROVER_assume(buf->b_data != NULL);
	buf->b_size = off + len;
	buf->b_len = len;
	buf->b_offset = off;
	return (buf);
}

void
rts_proof(void)
{
	struct piv_rts rts;
	struct apdubuf *buf;
	errf_t *err;

	buf = genapdubuf(12,12);
	bzero(&rts, sizeof (rts));
	err = piv_decode_rts(&rts, buf);
	__CPROVER_assume(err != ERRF_NOMEM);
	if (err != ERRF_OK)
		errf_free(err);
}

int
main(int argc, char *argv[])
{
	__CPROVER_assume(ERRF_NOMEM != NULL);
	rts_proof();
	return (0);
}

#endif
