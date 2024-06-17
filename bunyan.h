/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_BUNYAN_H)
#define _BUNYAN_H

#include <sys/types.h>
#include "errf.h"

enum bunyan_log_level {
	BNY_TRACE = 10,
	BNY_DEBUG = 20,
	BNY_INFO = 30,
	BNY_WARN = 40,
	BNY_ERROR = 50,
	BNY_FATAL = 60
};

enum bunyan_arg_type {
	BNY_STRING,
	BNY_INT,
	BNY_UINT,
	BNY_UINT64,
	BNY_SIZE_T,
	BNY_BIN_HEX,
	BNY_ERF,
	BNY_SSHKEY,
};

void bunyan_init(void);
void bunyan_unshare(void);
void bunyan_set_name(const char *name);
typedef void (*bunyan_printer_t)(enum bunyan_log_level, const char *);
void bunyan_set_printer(bunyan_printer_t printer, boolean_t omit_timestamp);
void bunyan_set_level(enum bunyan_log_level level);
enum bunyan_log_level bunyan_get_level(void);
void bunyan_log(enum bunyan_log_level level, const char *msg, ...);
struct bunyan_frame *_bunyan_push(const char *func, ...);
void bunyan_add_vars(struct bunyan_frame *frame, ...);
void bunyan_pop(struct bunyan_frame *frame);

#define	bunyan_push(...)	_bunyan_push(__func__, __VA_ARGS__)

#endif
