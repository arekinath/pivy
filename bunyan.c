/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
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
#include <inttypes.h>


#include "debug.h"

#include "bunyan.h"
#include "errf.h"
#include "utils.h"

#include "openssh/sshkey.h"

static const char *bunyan_name = NULL;

/*
 * This bunyan code was taken from the humboldt repo, where it used to run in
 * a multithreaded context and used thread-locals here for bunyan_buf etc.
 *
 * Unfortunately, pivy would like to be portable to platforms that don't support
 * thread-local annotations on variables (looking at you OpenBSD), so we've
 * removed those annotations here (and the mutexes) but left the remainder of
 * the code as-is.
 *
 * As a result this version of bunyan.c is completely unsafe to use in the
 * face of multi-threading. This is fine within the pivy repo where all we have
 * is a couple of single-threaded commandline tools, but if you re-use this
 * code elsewhere, beware!
 */

/*
 * This is called "bunyan.c" because it used to produce bunyan-compatible JSON
 * log lines as output. Now it just produces text loosely modelled after the
 * bunyan cmdline tool's output. C'est la vie in the land of wanting to be
 * portable to lots of other operating systems.
 */

static void
bunyan_default_printer(enum bunyan_log_level lvl, const char *msg)
{
	fprintf(stderr, "%s", msg);
}

static bunyan_printer_t bunyan_printer = bunyan_default_printer;
static char *bunyan_buf = NULL;
static size_t bunyan_buf_sz = 0;

static enum bunyan_log_level bunyan_min_level = BNY_WARN;
static boolean_t bunyan_omit_timestamp = B_FALSE;

struct bunyan_var {
	struct bunyan_var *bv_next;
	const char *bv_name;
	enum bunyan_arg_type bv_type;
	union {
		const char *bvv_string;
		int bvv_int;
		uint bvv_uint;
		uint64_t bvv_uint64;
		size_t bvv_size_t;
		struct {
			const uint8_t *bvvbh_data;
			size_t bvvbh_len;
		} bvv_bin_hex;
		errf_t *bvv_erf;
	} bv_value;
};
struct bunyan_frame {
	const char *bf_func;
	struct bunyan_frame *bf_next;
	struct bunyan_var *bf_vars;
	struct bunyan_var *bf_lastvar;
};
struct bunyan_stack {
	struct bunyan_stack *bs_next;
	struct bunyan_frame *bs_top;
};

static struct bunyan_stack *thstack;
static struct bunyan_stack *bunyan_stacks;

void
bunyan_set_level(enum bunyan_log_level level)
{
	bunyan_min_level = level;
}

void
bunyan_set_printer(bunyan_printer_t printer, boolean_t omit_timestamp)
{
	bunyan_printer = printer;
	bunyan_omit_timestamp = omit_timestamp;
}

enum bunyan_log_level
bunyan_get_level(void)
{
	return (bunyan_min_level);
}

static void
printf_buf(const char *fmt, ...)
{
	size_t orig, avail;
	int wrote;
	char *nbuf;
	va_list ap, ap2;

	if (bunyan_buf_sz == 0) {
		bunyan_buf_sz = 1024;
		bunyan_buf = calloc(bunyan_buf_sz, 1);
		VERIFY(bunyan_buf != NULL);
	}

	va_start(ap, fmt);

	/* Make a backup copy of the args so we can try again if we resize. */
	va_copy(ap2, ap);

	orig = strlen(bunyan_buf);
	avail = bunyan_buf_sz - orig;
again:
	wrote = vsnprintf(bunyan_buf + orig, avail, fmt, ap);
	VERIFY(wrote >= 0);
	if (wrote >= avail) {
		while (bunyan_buf_sz < orig + wrote)
			bunyan_buf_sz *= 2;
		nbuf = calloc(bunyan_buf_sz, 1);
		VERIFY(nbuf != NULL);
		bcopy(bunyan_buf, nbuf, orig);
		nbuf[orig] = 0;
		free(bunyan_buf);
		bunyan_buf = nbuf;

		avail = bunyan_buf_sz - orig;
		va_end(ap);
		va_copy(ap, ap2);
		goto again;
	}
	va_end(ap);
	va_end(ap2);
}

static void
reset_buf(void)
{
	if (bunyan_buf_sz > 0)
		bunyan_buf[0] = 0;
}

#if defined(__linux__)
static boolean_t
bunyan_detect_journald(void)
{
	char *envp;

	/*
	 * If journald is providing logging for this process, it will set
	 * JOURNAL_STREAM to <dev>:<inode>, corresponding to the device and
	 * inode of the socket attached to stderr and stdout.
	 */
	if ((envp = getenv("JOURNAL_STREAM")) != NULL) {
		char *p;
		unsigned long device, inode;
		struct stat info;

		errno = 0;
		device = strtoul(envp, &p, 10);
		if (errno != 0 || *p != ':')
			return (B_FALSE);
		errno = 0;
		inode = strtoul(++p, &p, 10);
		if (errno != 0 || *p != '\0')
			return (B_FALSE);

		if (fstat(STDERR_FILENO, &info) == 0) {
			if (info.st_dev == device &&
			    info.st_ino == inode) {
				return (B_TRUE);
			}
		}
	}

	return (B_FALSE);
}
#endif /* defined (__linux__) */

void
bunyan_init(void)
{
#if defined(__linux__)
	/*
	 * When logging to journald, generating our own timestamps is
	 * unecessary as the journal has its own native ones.
	 */
	if (bunyan_detect_journald()) {
		bunyan_omit_timestamp = B_TRUE;
	}
#endif
}

void
bunyan_set_name(const char *name)
{
	bunyan_name = name;
}

#define	MAX_TS_LEN	128

void
bunyan_timestamp(char *buffer, size_t len)
{
	struct timespec ts;
	struct tm *info;
	int w;

	VERIFY0(clock_gettime(CLOCK_REALTIME, &ts));
	info = gmtime(&ts.tv_sec);
	VERIFY(info != NULL);

	w = snprintf(buffer, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
	    info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
	    info->tm_hour, info->tm_min, info->tm_sec, ts.tv_nsec / 1000000);
	VERIFY(w < MAX_TS_LEN);
}

static void
bunyan_add_vars_p(struct bunyan_frame *frame, va_list ap)
{
	struct bunyan_var *var = frame->bf_lastvar;
	const char *propname;

	while (1) {
		propname = va_arg(ap, const char *);

		if (propname == NULL)
			break;

		if (var == NULL) {
			frame->bf_vars = (var =
			    calloc(1, sizeof (struct bunyan_var)));
			VERIFY(var != NULL);
		} else {
			var->bv_next = calloc(1, sizeof (struct bunyan_var));
			var = var->bv_next;
			VERIFY(var != NULL);
		}

		var->bv_name = propname;
		var->bv_type = va_arg(ap, enum bunyan_arg_type);

		switch (var->bv_type) {
		case BNY_STRING:
			var->bv_value.bvv_string = va_arg(ap, const char *);
			break;
		case BNY_INT:
			var->bv_value.bvv_int = va_arg(ap, int);
			break;
		case BNY_UINT:
			var->bv_value.bvv_uint = va_arg(ap, uint);
			break;
		case BNY_UINT64:
			var->bv_value.bvv_uint64 = va_arg(ap, uint64_t);
			break;
		case BNY_SIZE_T:
			var->bv_value.bvv_size_t = va_arg(ap, size_t);
			break;
		case BNY_BIN_HEX:
			var->bv_value.bvv_bin_hex.bvvbh_data =
			    va_arg(ap, const uint8_t *);
			var->bv_value.bvv_bin_hex.bvvbh_len =
			    va_arg(ap, size_t);
			break;
		case BNY_ERF:
			var->bv_value.bvv_erf = va_arg(ap, errf_t *);
			break;
		default:
			abort();
		}
	}

	frame->bf_lastvar = var;
}

void
bunyan_add_vars(struct bunyan_frame *frame, ...)
{
	va_list ap;
	va_start(ap, frame);
	bunyan_add_vars_p(frame, ap);
	va_end(ap);
}

struct bunyan_frame *
_bunyan_push(const char *func, ...)
{
	va_list ap;
	struct bunyan_frame *frame;

	frame = calloc(1, sizeof (struct bunyan_frame));
	VERIFY(frame != NULL);
	frame->bf_func = func;

	va_start(ap, func);
	bunyan_add_vars_p(frame, ap);
	va_end(ap);

	if (thstack == NULL) {
		thstack = calloc(1, sizeof (struct bunyan_stack));
		VERIFY(thstack != NULL);
		thstack->bs_next = bunyan_stacks;
		bunyan_stacks = thstack;
	}

	frame->bf_next = thstack->bs_top;
	thstack->bs_top = frame;

	return (frame);
}

void
bunyan_pop(struct bunyan_frame *frame)
{
	struct bunyan_var *var, *nvar;
	VERIFY(frame != NULL);
	VERIFY(thstack != NULL);
	VERIFY(thstack->bs_top == frame);
	thstack->bs_top = frame->bf_next;

	for (var = frame->bf_vars; var != NULL; var = nvar) {
		nvar = var->bv_next;
		free(var);
	}
	free(frame);
}

static void
print_frame(struct bunyan_frame *frame, uint *pn, struct bunyan_var **evars)
{
	struct bunyan_var *var;
	uint n = *pn;
	struct bunyan_var *evar;
	char *wstrval;

	for (var = frame->bf_vars; var != NULL; var = var->bv_next, ++n) {
		if (n == 0) {
			printf_buf(": ");
		} else {
			printf_buf(", ");
		}

		switch (var->bv_type) {
		case BNY_STRING:
			printf_buf("%s = \"%s\"", var->bv_name,
			    var->bv_value.bvv_string);
			break;
		case BNY_INT:
			printf_buf("%s = %d", var->bv_name,
			    var->bv_value.bvv_int);
			break;
		case BNY_UINT:
			printf_buf("%s = 0x%x", var->bv_name,
			    var->bv_value.bvv_uint);
			break;
		case BNY_UINT64:
			printf_buf("%s = 0x%" PRIx64, var->bv_name,
			    var->bv_value.bvv_uint64);
			break;
		case BNY_SIZE_T:
			printf_buf("%s = %zu", var->bv_name,
			    var->bv_value.bvv_size_t);
			break;
		case BNY_BIN_HEX:
			wstrval = buf_to_hex(
			    var->bv_value.bvv_bin_hex.bvvbh_data,
			    var->bv_value.bvv_bin_hex.bvvbh_len, 1);
			printf_buf("%s = << %s >>", var->bv_name, wstrval);
			free(wstrval);
			break;
		case BNY_ERF:
			evar = calloc(1, sizeof (struct bunyan_var));
			VERIFY(evar != NULL);
			bcopy(var, evar, sizeof (struct bunyan_var));
			evar->bv_next = *evars;
			*evars = evar;
			printf_buf("%s = %s...", var->bv_name,
			    errf_name(var->bv_value.bvv_erf));
			break;
		default:
			abort();
		}
	}

	*pn = n;
}

void
bunyan_log(enum bunyan_log_level level, const char *msg, ...)
{
	va_list ap;
	const char *propname;
	errf_t *err = NULL;
	enum bunyan_arg_type typ;
	uint n = 0;
	struct bunyan_frame *frame;
	struct bunyan_var *evars = NULL, *evar, *nevar;

	reset_buf();

	if (!bunyan_omit_timestamp) {
		char time[MAX_TS_LEN];

		bunyan_timestamp(time, sizeof (time));
		printf_buf("[%s] ", time);
	}

	if (bunyan_printer == bunyan_default_printer) {
		switch (level) {
		case BNY_TRACE:
			printf_buf("TRACE: ");
			break;
		case BNY_DEBUG:
			printf_buf("DEBUG: ");
			break;
		case BNY_INFO:
			printf_buf("INFO: ");
			break;
		case BNY_WARN:
			printf_buf("WARN: ");
			break;
		case BNY_ERROR:
			printf_buf("ERROR: ");
			break;
		case BNY_FATAL:
			printf_buf("FATAL: ");
			break;
		}
	}

	printf_buf("%s", msg);

	if (thstack != NULL) {
		frame = thstack->bs_top;
		for (; frame != NULL; frame = frame->bf_next) {
			print_frame(frame, &n, &evars);
		}
	}

	va_start(ap, msg);
	while (1) {
		const char *strval;
		char *wstrval;
		const uint8_t *binval;
		int intval;
		uint uintval;
		uint64_t uint64val;
		size_t szval;
		struct sshkey *pubk;

		propname = va_arg(ap, const char *);
		if (propname == NULL)
			break;

		if (n == 0) {
			printf_buf(": ");
		} else {
			printf_buf(", ");
		}
		++n;

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
			printf_buf("%s = 0x%" PRIx64, propname, uint64val);
			break;
		case BNY_SIZE_T:
			szval = va_arg(ap, size_t);
			printf_buf("%s = %zu", propname, szval);
			break;
		case BNY_BIN_HEX:
			binval = va_arg(ap, const uint8_t *);
			szval = va_arg(ap, size_t);
			wstrval = buf_to_hex(binval, szval, 1);
			printf_buf("%s = << %s >>", propname, wstrval);
			free(wstrval);
			break;
		case BNY_ERF:
			err = va_arg(ap, errf_t *);
			printf_buf("%s = %s...", propname, errf_name(err));

			evar = calloc(1, sizeof (struct bunyan_var));
			VERIFY(evar != NULL);
			evar->bv_name = propname;
			evar->bv_value.bvv_erf = err;

			evar->bv_next = evars;
			evars = evar;
			break;
		case BNY_SSHKEY:
			pubk = va_arg(ap, struct sshkey *);
			wstrval = sshkey_fingerprint(pubk, SSH_DIGEST_SHA256,
			    SSH_FP_BASE64);
			printf_buf("%s = %s key (%u bits): %s", propname,
			    sshkey_type(pubk), sshkey_size(pubk), wstrval);
			free(wstrval);
			break;
		default:
			abort();
		}
	}
	va_end(ap);
	printf_buf("\n");

	for (evar = evars; evar != NULL; evar = nevar) {
		const char *prefix = "";
		nevar = evar->bv_next;
		printf_buf("\t%s = ", evar->bv_name);
		err = evar->bv_value.bvv_erf;
		for (; err != NULL; err = errf_cause(err)) {
			printf_buf("%s%s: %s\n\t    in %s() at %s:%d\n", prefix,
			    errf_name(err), errf_message(err),
			    errf_function(err), errf_file(err), errf_line(err));
			prefix = "\t  Caused by ";
		}
		free(evar);
	}

	if (level < bunyan_min_level) {
		return;
	}
	(*bunyan_printer)(level, bunyan_buf);
}
