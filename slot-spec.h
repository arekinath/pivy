/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2023 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
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
errf_t		*slotspec_parse_pe(struct slotspec *, const char *,
    const char *);

void	 slotspec_set(struct slotspec *, enum piv_slotid slot);
void	 slotspec_clear(struct slotspec *, enum piv_slotid slot);
void	 slotspec_set_default(struct slotspec *);
void	 slotspec_clear_all(struct slotspec *);
int	 slotspec_test(const struct slotspec *, enum piv_slotid slot);

#endif	/* !_SLOT_SPEC_H */
