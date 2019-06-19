/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_UTILS_H)
#define _UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#if !defined(__APPLE__)
typedef uint64_t uintmax_t;
#endif

#if !defined(USING_SPL)
typedef /*@concrete@*/ enum { B_FALSE = 0, B_TRUE = 1 } boolean_t;
typedef /*@concrete@*/ unsigned int uint;
#endif

#if !defined(__OpenBSD__)
void *malloc_conceal(size_t size) __attribute__((malloc));
void *calloc_conceal(size_t nmemb, size_t size) __attribute__((malloc));
#endif

void set_no_dump(void *ptr, size_t size);

#if !defined(__OpenBSD__) && !defined(__sun)
void freezero(void *ptr, size_t size);
#endif

char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

#endif
