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

#if !defined(__APPLE__) && !defined(__sun)
typedef uint64_t uintmax_t;
#endif

#if !defined(USING_SPL) && !defined(__sun)
typedef enum { B_FALSE = 0, B_TRUE = 1 } boolean_t;
typedef unsigned int uint;
typedef unsigned int u_int;
#endif

void *malloc_conceal(size_t size) __attribute__((malloc));
void *calloc_conceal(size_t nmemb, size_t size) __attribute__((malloc));

void set_no_dump(void *ptr, size_t size);

#if !defined(__OpenBSD__) && !defined(__sun)
void freezero(void *ptr, size_t size);
#endif

char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

#if defined(__bounded)
#undef __bounded
#endif

#if defined(HAVE_BOUNDED_ATTR)
#define __bounded(_what, ...) __attribute__((__bounded__(_what, __VA_ARG__)))
#else
#define __bounded(_what, ...)
#endif

#if defined(__APPLE__)
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

void *reallocarray(void *, size_t, size_t);
void explicit_bzero(void *, size_t);
#endif

#endif
