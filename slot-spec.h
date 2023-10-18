/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2023, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_SLOT_SPEC_H)
#define _SLOT_SPEC_H

#include <stdint.h>
#include "errf.h"
#include "piv.h"

struct slotspec;

struct slotspec *slotspec_alloc(void);
void		 slotspec_free(struct slotspec *);
errf_t		*slotspec_parse(struct slotspec *, const char *);

void	 slotspec_set(struct slotspec *, enum piv_slotid slot);
void	 slotspec_clear(struct slotspec *, enum piv_slotid slot);
int	 slotspec_test(const struct slotspec *, enum piv_slotid slot);

#endif	/* !_SLOT_SPEC_H */
