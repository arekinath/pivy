/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>

#include "bunyan.h"
#include "debug.h"

static const char *bunyan_name = NULL;
static const char *bunyan_hostname = NULL;
static char *bunyan_buf = NULL;
static size_t bunyan_buf_sz = 0;
static enum bunyan_log_level bunyan_min_level = INFO;

struct bunyan_timers {
	struct timer_block *bt_first;
	struct timer_block *bt_last;
	struct timespec bt_current;
};

#define	TBLOCK_N	16
struct timer_block {
	struct timespec tb_timers[TBLOCK_N];
	const char *tb_names[TBLOCK_N];
	size_t tb_pos;
	struct timer_block *tb_next;
};

#define	NS_PER_S	1000000000ULL

static inline char
nybble_to_hex(uint8_t nybble)
{
	if (nybble >= 0xA)
		return ('A' + (nybble - 0xA));
	else
		return ('0' + nybble);
}

char *
buf_to_hex(const uint8_t *buf, size_t len, int spaces)
{
	size_t i, j = 0;
	char *out = calloc(1, len * 3 + 1);
	uint8_t nybble;
	for (i = 0; i < len; ++i) {
		nybble = (buf[i] & 0xF0) >> 4;
		out[j++] = nybble_to_hex(nybble);
		nybble = (buf[i] & 0x0F);
		out[j++] = nybble_to_hex(nybble);
		if (spaces && i + 1 < len)
			out[j++] = ' ';
	}
	out[j] = 0;
	return (out);
}

void
tspec_subtract(struct timespec *result, const struct timespec *x,
    const struct timespec *y)
{
	struct timespec xcarry;
	bcopy(x, &xcarry, sizeof (xcarry));
	if (xcarry.tv_nsec < y->tv_nsec) {
		xcarry.tv_sec -= 1;
		xcarry.tv_nsec += NS_PER_S;
	}
	result->tv_sec = xcarry.tv_sec - y->tv_sec;
	result->tv_nsec = xcarry.tv_nsec - y->tv_nsec;
}

void
bunyan_set_level(enum bunyan_log_level level)
{
	bunyan_min_level = level;
}

struct bunyan_timers *
bny_timers_new(void)
{
	struct bunyan_timers *tms;
	tms = calloc(1, sizeof (struct bunyan_timers));
	if (tms == NULL)
		return (NULL);
	tms->bt_first = calloc(1, sizeof (struct timer_block));
	if (tms->bt_first == NULL) {
		free(tms);
		return (NULL);
	}
	tms->bt_last = tms->bt_first;
	return (tms);
}


int
bny_timer_begin(struct bunyan_timers *tms)
{
	if (clock_gettime(CLOCK_MONOTONIC, &tms->bt_current))
		return (errno);
	return (0);
}

int
bny_timer_next(struct bunyan_timers *tms, const char *name)
{
	struct timespec now;
	struct timer_block *b;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return (errno);
	b = tms->bt_last;
	b->tb_names[b->tb_pos] = name;
	tspec_subtract(&b->tb_timers[b->tb_pos], &now, &tms->bt_current);
	if (++b->tb_pos >= TBLOCK_N) {
		b = calloc(1, sizeof (struct timer_block));
		if (b == NULL) {
			tms->bt_last->tb_pos--;
			return (ENOMEM);
		}
		tms->bt_last->tb_next = b;
		tms->bt_last = b;
		if (clock_gettime(CLOCK_MONOTONIC, &tms->bt_current))
			return (errno);
	} else {
		bcopy(&now, &tms->bt_current, sizeof (struct timespec));
	}
	return (0);
}

void
bny_timers_free(struct bunyan_timers *tms)
{
	struct timer_block *b, *nb;
	for (b = tms->bt_first; b != NULL; b = nb) {
		nb = b->tb_next;
		free(b);
	}
	free(tms);
}

static void
printf_buf(const char *fmt, ...)
{
	size_t wrote, orig, avail;
	char *nbuf;
	va_list ap;

	if (bunyan_buf_sz == 0) {
		bunyan_buf_sz = 1024;
		bunyan_buf = calloc(bunyan_buf_sz, 1);
		VERIFY(bunyan_buf != NULL);
	}

	va_start(ap, fmt);
	orig = strlen(bunyan_buf);
	avail = bunyan_buf_sz - orig;
again:
	wrote = vsnprintf(bunyan_buf + orig, avail, fmt, ap);
	if (wrote >= avail) {
		bunyan_buf_sz *= 2;
		nbuf = calloc(bunyan_buf_sz, 1);
		VERIFY(nbuf != NULL);
		bcopy(bunyan_buf, nbuf, orig);
		nbuf[orig] = 0;
		free(bunyan_buf);
		bunyan_buf = nbuf;

		avail = bunyan_buf_sz - orig;
		goto again;
	}
	va_end(ap);
}

static void
reset_buf(void)
{
	if (bunyan_buf_sz > 0)
		bunyan_buf[0] = 0;
}

static int
bny_timer_print(struct bunyan_timers *tms)
{
	struct timer_block *b;
	size_t idx;
	uint64_t usec;
	int rv;

	for (b = tms->bt_first; b != NULL; b = b->tb_next) {
		for (idx = 0; idx < b->tb_pos; ++idx) {
			usec = b->tb_timers[idx].tv_nsec / 1000;
			usec += b->tb_timers[idx].tv_sec * 1000000;
			printf_buf("[%s: %llu usec]", b->tb_names[idx], usec);
		}
	}
	return (0);
}

void
bunyan_init(void)
{
}

void
bunyan_set_name(const char *name)
{
	bunyan_name = name;
}

static void
bunyan_get_hostname(void)
{
}

void
bunyan_timestamp(char *buffer, size_t len)
{
	struct timespec ts;
	struct tm *info;

	VERIFY0(clock_gettime(CLOCK_REALTIME, &ts));
	info = gmtime(&ts.tv_sec);
	VERIFY(info != NULL);

	snprintf(buffer, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
	    info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
	    info->tm_hour, info->tm_min, info->tm_sec, ts.tv_nsec / 1000000);
}

void
bunyan_set(const char *name1, enum bunyan_arg_type typ1, ...)
{
	abort();
}

void
bunyan_log(enum bunyan_log_level level, const char *msg, ...)
{
	char time[128];
	va_list ap;
	const char *propname;
	enum bunyan_arg_type typ;
	int didsep = 0;

	reset_buf();

	bunyan_timestamp(time, sizeof (time));
	printf_buf("[%s] ", time);

	switch (level) {
	case TRACE:
		printf_buf("TRACE: ");
		break;
	case DEBUG:
		printf_buf("DEBUG: ");
		break;
	case INFO:
		printf_buf("INFO: ");
		break;
	case WARN:
		printf_buf("WARN: ");
		break;
	case ERROR:
		printf_buf("ERROR: ");
		break;
	case FATAL:
		printf_buf("FATAL: ");
		break;
	}

	printf_buf("%s", msg);

	va_start(ap, msg);
	while (1) {
		const char *strval;
		char *wstrval;
		const uint8_t *binval;
		int intval;
		uint uintval;
		uint64_t uint64val;
		size_t szval;
		struct bunyan_timers *tsval;

		propname = va_arg(ap, const char *);
		if (propname == NULL)
			break;

		if (!didsep) {
			didsep = 1;
			printf_buf(": ");
		} else {
			printf_buf(", ");
		}

		typ = va_arg(ap, enum bunyan_arg_type);

		switch (typ) {
		case BNY_STRING:
			strval = va_arg(ap, const char *);
			printf_buf("%s = \"%s\"", propname, strval);
			break;
		case BNY_INT:
			intval = va_arg(ap, int);
			printf_buf("%s = %d", propname, intval);
			break;
		case BNY_UINT:
			uintval = va_arg(ap, uint);
			printf_buf("%s = 0x%x", propname, uintval);
			break;
		case BNY_UINT64:
			uint64val = va_arg(ap, uint64_t);
			printf_buf("%s = 0x%llx", propname, uint64val);
			break;
		case BNY_SIZE_T:
			szval = va_arg(ap, size_t);
			printf_buf("%s = %llu", propname, szval);
			break;
		case BNY_NVLIST:
			abort();
			break;
		case BNY_TIMERS:
			tsval = va_arg(ap, struct bunyan_timers *);
			VERIFY0(bny_timer_print(tsval));
			break;
		case BNY_BIN_HEX:
			binval = va_arg(ap, const uint8_t *);
			szval = va_arg(ap, size_t);
			wstrval = buf_to_hex(binval, szval, 1);
			printf_buf("%s = << %s >>", propname, wstrval);
			free(wstrval);
			break;
		default:
			abort();
		}
	}
	va_end(ap);
	printf_buf("\n");

	if (level < bunyan_min_level) {
		return;
	}
	fprintf(stderr, bunyan_buf);
}
