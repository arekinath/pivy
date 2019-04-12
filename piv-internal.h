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

struct piv_ecdh_box {
	uint8_t pdb_version;
	boolean_t pdb_guidslot_valid;
	uint8_t pdb_guid[16];
	enum piv_slotid pdb_slot;

	struct sshkey *pdb_ephem;
	struct sshkey *pdb_ephem_pub;
	struct sshkey *pdb_pub;

	boolean_t pdb_free_str;
	const char *pdb_cipher;
	const char *pdb_kdf;

	struct apdubuf pdb_nonce;
	struct apdubuf pdb_iv;
	struct apdubuf pdb_enc;
	struct apdubuf pdb_plain;
};

enum piv_box_version {
	PIV_BOX_V1 = 0x01,
	PIV_BOX_V2 = 0x02,
	PIV_BOX_VNEXT
};

#endif
