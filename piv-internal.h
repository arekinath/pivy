/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_PIV_INTERNAL_H)
#define	_PIV_INTERNAL_H

/*
 * This file contains some internal (non-public) API of piv.c.
 * It's useful to be able to share this between the piv and ebox code, but
 * nothing outside them should be using it.
 */

#include "piv.h"

struct apdubuf {
	uint8_t *b_data;
	size_t b_offset;
	size_t b_size;
	size_t b_len;
};

enum piv_box_version {
	PIV_BOX_V1 = 0x01,
	/* Version 2 added the nonce field. */
	PIV_BOX_V2 = 0x02,
	PIV_BOX_VNEXT
};

struct piv_ecdh_box {
	/* Actually one of the piv_box_version values */
	uint8_t pdb_version;

	/* If true, the pdb_guid/pdb_slot fields are populated. */
	boolean_t pdb_guidslot_valid;
	uint8_t pdb_guid[16];
	enum piv_slotid pdb_slot;

	/* Cached cstring hex version of pdb_guid */
	char *pdb_guidhex;

	/* The ephemeral public key that does DH with pdb_pub */
	struct sshkey *pdb_ephem_pub;
	/* The public key we intend to be able to unlock the box */
	struct sshkey *pdb_pub;

	/*
	 * If true, pdb_cipher/kdf were malloc'd by us and should be freed
	 * in piv_box_free()
	 */
	boolean_t pdb_free_str;
	const char *pdb_cipher;		/* OpenSSH cipher.c alg name */
	const char *pdb_kdf;		/* OpenSSH digest.c alg name */

	struct apdubuf pdb_nonce;
	struct apdubuf pdb_iv;
	struct apdubuf pdb_enc;

	/*
	 * Never written out as part of the box structure: the in-memory
	 * cached plaintext after we unseal a box goes here.
	 */
	struct apdubuf pdb_plain;

	/*
	 * This is for ebox to use to supply an alternative ephemeral _private_
	 * key for sealing (nobody else should use this!)
	 */
	struct sshkey *pdb_ephem;
};

/* Certinfo flags with certificates. Is it compressed? How? */
enum piv_cert_comp {
	PIV_COMP_GZIP = 1,
	PIV_COMP_NONE = 0,
};

enum piv_certinfo_flags {
	PIV_CI_X509 = (1 << 2),
	PIV_CI_COMPTYPE = 0x03,
};

#endif
