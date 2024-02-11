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

%%{
machine slotspec;

action set_inv { invert = B_TRUE; }
action clear_inv { invert = B_FALSE; }
action set_all { mask = 0x743ffffc; }
action start_slot { slotp = p; slotpe = NULL; }
action end_slot {
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
action update_mask {
	if (invert)
		spec->ss_mask &= ~mask;
	else
		spec->ss_mask |= mask;
}
action slot_err {
	return (errf("InvalidSlot", NULL, "Invalid slot spec at: '%s'",
	    p - 1));
}
action inv_err {
	return (errf("InvalidSlotSpec", NULL, "Invalid inverse spec: '%s' "
	    "(expected '!' and then a slot)", p - 1));
}

ws = [ \t]+;
all = 'all' %set_all %update_mask;
slotstr = [0-9a-zA-Z]+ >1 $2 %1 >start_slot %end_slot %update_mask;
baseslot = (all @2) | (slotstr @1) @err(slot_err);
invslot = '!' ws? baseslot >1 $2 %1 >set_inv %clear_inv @err(inv_err);
slot = invslot | baseslot @err(slot_err);
main := ws? slot (ws? ',' ws? slot)*;
}%%

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

%% write data;

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

	%% write init;
	%% write exec;

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
