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
	char erf_name[128];
	char erf_message[256];
	const char *erf_function;
	const char *erf_file;
	uint erf_line;
};
typedef struct erf erf_t;

void perf(const struct erf *e);
void perfexit(const struct erf *e);
int erfcause(const struct erf *e, const char *name);
void erfree(struct erf *e);

extern struct erf *ERF_OK;
extern struct erf *ERF_NOMEM;

struct erf *_erf(const char *name, struct erf *cause, const char *func,
    const char *file, uint line, const char *fmt, ...);

struct erf *_erfno(int eno, const char *func, const char *file, uint line,
    const char *fmt, ...);

#define erf(name, cause, fmt, ...)	\
    _erf(name, cause, __func__, __FILE__, __LINE__, \
    fmt __VA_OPT__(,) __VA_ARGS__)

#define erfno(eno, fmt, ...)	\
    _erfno(eno, __func__, __FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

#endif
