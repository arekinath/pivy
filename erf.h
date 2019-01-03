/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_ERF_H)
#define _ERF_H

#include <stdint.h>
#include <sys/types.h>

struct erf {
	struct erf *erf_cause;
	int erf_errno;
	const char *erf_name;
	const char *erf_message;
	const char *erf_file;
	uint erf_line;
};

void perf(struct erf *e);
void perfexit(struct erf *e);

extern struct erf *ERF_OK;
extern struct erf *ERF_NOMEM;

struct erf *_erf(const char *name, struct erf *cause, const char *file,
    uint line, const char *fmt, ...);

struct erf *_erfno(int errno, const char *file, uint line, const char *fmt,
    ...);

#define erf(name, cause, fmt, ...)	\
    do { _erf(name, cause, __FILE__, __LINE__, fmt, __VA_ARGS__) } while (0)

#define erfno(errno, fmt, ...)	\
    do { _erf(errno, __FILE__, __LINE__, fmt, __VA_ARGS__) } while (0)

#endif
