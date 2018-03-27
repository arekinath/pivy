/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_BUNYAN_H)
#define _BUNYAN_H

enum bunyan_log_level {
	TRACE = 10,
	DEBUG = 20,
	INFO = 30,
	WARN = 40,
	ERROR = 50,
	FATAL = 60
};

enum bunyan_arg_type {
	BNY_STRING,
	BNY_INT,
	BNY_UINT,
	BNY_UINT64,
	BNY_SIZE_T,
	BNY_NVLIST,
	BNY_TIMERS,
	BNY_BIN_HEX,
};

void bunyan_init(void);
void bunyan_unshare(void);
void bunyan_set_name(const char *name);
void bunyan_set_level(enum bunyan_log_level level);
void bunyan_log(enum bunyan_log_level level, const char *msg, ...);
void bunyan_set(const char *name1, enum bunyan_arg_type typ1, ...);

struct bunyan_timers *bny_timers_new(void);
int bny_timer_begin(struct bunyan_timers *tms);
int bny_timer_next(struct bunyan_timers *tms, const char *name);
void bny_timers_free(struct bunyan_timers *tms);

#endif
