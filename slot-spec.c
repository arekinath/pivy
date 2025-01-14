
#line 1 "slot-spec.rl"
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2023 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "debug.h"
#include "slot-spec.h"

struct slotspec {
	uint64_t	ss_mask;
};


#line 75 "slot-spec.rl"


struct slotspec *
slotspec_alloc(void)
{
	struct slotspec *spec;
	spec = calloc(1, sizeof (*spec));
	spec->ss_mask = 0x743ffffc;
	return (spec);
}

void
slotspec_free(struct slotspec *spec)
{
	free(spec);
}

void
slotspec_set(struct slotspec *spec, enum piv_slotid slotid)
{
	unsigned long int parsed;
	parsed = slotid;
	parsed &= 0x7f;
	assert(parsed <= 63);
	spec->ss_mask |= (1ull << parsed);
}

void
slotspec_clear(struct slotspec *spec, enum piv_slotid slotid)
{
	unsigned long int parsed;
	parsed = slotid;
	parsed &= 0x7f;
	assert(parsed <= 63);
	spec->ss_mask &= ~(1ull << parsed);
}

int
slotspec_test(const struct slotspec *spec, enum piv_slotid slotid)
{
	unsigned long int parsed;
	parsed = slotid;
	parsed &= 0x7f;
	assert(parsed <= 63);
	return ((spec->ss_mask & (1ull << parsed)) != 0);
}

void
slotspec_set_default(struct slotspec *spec)
{
	spec->ss_mask = 0x743ffffc;
}

void
slotspec_clear_all(struct slotspec *spec)
{
	spec->ss_mask = 0;
}


#line 83 "slot-spec.c"
static const char _slotspec_actions[] = {
	0, 1, 3, 1, 6, 2, 0, 3, 
	2, 2, 5, 2, 4, 5, 2, 6, 
	7, 3, 2, 5, 1, 3, 4, 5, 
	1
};

static const char _slotspec_key_offsets[] = {
	0, 0, 10, 19, 22, 31, 41, 51, 
	54, 63, 73, 83
};

static const char _slotspec_trans_keys[] = {
	9, 32, 33, 97, 48, 57, 65, 90, 
	98, 122, 9, 32, 97, 48, 57, 65, 
	90, 98, 122, 9, 32, 44, 9, 32, 
	44, 48, 57, 65, 90, 97, 122, 9, 
	32, 44, 108, 48, 57, 65, 90, 97, 
	122, 9, 32, 44, 108, 48, 57, 65, 
	90, 97, 122, 9, 32, 44, 9, 32, 
	44, 48, 57, 65, 90, 97, 122, 9, 
	32, 44, 108, 48, 57, 65, 90, 97, 
	122, 9, 32, 44, 108, 48, 57, 65, 
	90, 97, 122, 9, 32, 44, 0
};

static const char _slotspec_single_lengths[] = {
	0, 4, 3, 3, 3, 4, 4, 3, 
	3, 4, 4, 3
};

static const char _slotspec_range_lengths[] = {
	0, 3, 3, 0, 3, 3, 3, 0, 
	3, 3, 3, 0
};

static const char _slotspec_index_offsets[] = {
	0, 0, 8, 15, 19, 26, 34, 42, 
	46, 53, 61, 69
};

static const char _slotspec_indicies[] = {
	1, 1, 2, 4, 3, 3, 3, 0, 
	2, 2, 7, 6, 6, 6, 5, 8, 
	8, 1, 9, 10, 10, 11, 12, 12, 
	12, 9, 10, 10, 11, 13, 12, 12, 
	12, 9, 10, 10, 11, 14, 12, 12, 
	12, 9, 15, 15, 16, 9, 17, 17, 
	18, 19, 19, 19, 9, 17, 17, 18, 
	20, 19, 19, 19, 9, 17, 17, 18, 
	21, 19, 19, 19, 9, 22, 22, 23, 
	9, 0
};

static const char _slotspec_trans_targs[] = {
	0, 1, 2, 8, 9, 0, 4, 5, 
	3, 0, 3, 1, 4, 6, 7, 3, 
	1, 3, 1, 8, 10, 11, 3, 1
};

static const char _slotspec_trans_actions[] = {
	3, 0, 0, 1, 1, 14, 5, 5, 
	0, 0, 21, 21, 0, 0, 0, 17, 
	17, 11, 11, 0, 0, 0, 8, 8
};

static const char _slotspec_eof_actions[] = {
	0, 3, 14, 0, 21, 21, 21, 17, 
	11, 11, 11, 8
};

static const int slotspec_start = 1;
static const int slotspec_first_final = 4;
static const int slotspec_error = 0;

static const int slotspec_en_main = 1;


#line 135 "slot-spec.rl"

errf_t *
slotspec_parse_pe(struct slotspec *spec, const char *p, const char *pe)
{
	const char *eof = pe;
	boolean_t invert = B_FALSE;
	enum piv_slotid slotid;
	const char *slotp = NULL, *slotpe = NULL;
	char *slot;
	uint64_t mask = 0;
	errf_t *err = ERRF_OK;
	unsigned long int parsed;
	int cs;

	
#line 174 "slot-spec.c"
	{
	cs = slotspec_start;
	}

#line 150 "slot-spec.rl"
	
#line 177 "slot-spec.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _slotspec_trans_keys + _slotspec_key_offsets[cs];
	_trans = _slotspec_index_offsets[cs];

	_klen = _slotspec_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _slotspec_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _slotspec_indicies[_trans];
	cs = _slotspec_trans_targs[_trans];

	if ( _slotspec_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _slotspec_actions + _slotspec_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 26 "slot-spec.rl"
	{ invert = B_TRUE; }
	break;
	case 1:
#line 27 "slot-spec.rl"
	{ invert = B_FALSE; }
	break;
	case 2:
#line 28 "slot-spec.rl"
	{ mask = 0x743ffffc; }
	break;
	case 3:
#line 29 "slot-spec.rl"
	{ slotp = p; slotpe = NULL; }
	break;
	case 4:
#line 30 "slot-spec.rl"
	{
	slotpe = p;
	slot = strndup(slotp, slotpe - slotp);
	err = piv_slotid_from_string(slot, &slotid);
	if (err != ERRF_OK) {
		err = errf("ParseError", err,
		    "Failed to parse slot id: '%s'", slot);
		free(slot);
		return (err);
	}
	parsed = slotid;
	parsed &= 0x7f;
	if (parsed > 63) {
		err = errf("InvalidSlot", NULL,
		    "Invalid slot id: '%s'", slot);
		free(slot);
		return (err);
	}
	free(slot);
	slot = NULL;
	slotp = NULL;
	mask = (1ull << parsed);
}
	break;
	case 5:
#line 53 "slot-spec.rl"
	{
	if (invert)
		spec->ss_mask &= ~mask;
	else
		spec->ss_mask |= mask;
}
	break;
	case 6:
#line 59 "slot-spec.rl"
	{
	return (errf("InvalidSlot", NULL, "Invalid slot spec at: '%s'",
	    p - 1));
}
	break;
	case 7:
#line 63 "slot-spec.rl"
	{
	return (errf("InvalidSlotSpec", NULL, "Invalid inverse spec: '%s' "
	    "(expected '!' and then a slot)", p - 1));
}
	break;
#line 307 "slot-spec.c"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _slotspec_actions + _slotspec_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 1:
#line 27 "slot-spec.rl"
	{ invert = B_FALSE; }
	break;
	case 2:
#line 28 "slot-spec.rl"
	{ mask = 0x743ffffc; }
	break;
	case 4:
#line 30 "slot-spec.rl"
	{
	slotpe = p;
	slot = strndup(slotp, slotpe - slotp);
	err = piv_slotid_from_string(slot, &slotid);
	if (err != ERRF_OK) {
		err = errf("ParseError", err,
		    "Failed to parse slot id: '%s'", slot);
		free(slot);
		return (err);
	}
	parsed = slotid;
	parsed &= 0x7f;
	if (parsed > 63) {
		err = errf("InvalidSlot", NULL,
		    "Invalid slot id: '%s'", slot);
		free(slot);
		return (err);
	}
	free(slot);
	slot = NULL;
	slotp = NULL;
	mask = (1ull << parsed);
}
	break;
	case 5:
#line 53 "slot-spec.rl"
	{
	if (invert)
		spec->ss_mask &= ~mask;
	else
		spec->ss_mask |= mask;
}
	break;
	case 6:
#line 59 "slot-spec.rl"
	{
	return (errf("InvalidSlot", NULL, "Invalid slot spec at: '%s'",
	    p - 1));
}
	break;
	case 7:
#line 63 "slot-spec.rl"
	{
	return (errf("InvalidSlotSpec", NULL, "Invalid inverse spec: '%s' "
	    "(expected '!' and then a slot)", p - 1));
}
	break;
#line 373 "slot-spec.c"
		}
	}
	}

	_out: {}
	}

#line 151 "slot-spec.rl"

	if (cs == slotspec_error) {
		err = errf("InvalidSlotSpec", NULL, "Unexpected '%c'",
		    *p);
	} else if (cs < slotspec_first_final) {
		err = errf("InvalidSlotSpec", NULL, "Slot spec truncated?");
	}
	(void)slotspec_en_main;

	return (err);
}

errf_t *
slotspec_parse(struct slotspec *spec, const char *p)
{
	const char *pe = p + strlen(p);
	return (slotspec_parse_pe(spec, p, pe));
}
