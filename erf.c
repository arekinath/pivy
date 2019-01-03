/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>

#include "erf.h"

const char *
errno_to_macro(int errno)
{
	switch (errno) {
	case EPERM: return ("EPERM");
	case ENOENT: return ("ENOENT");
	case ESRCH: return ("ESRCH");
	case EINTR: return ("EINTR");
	case EIO: return ("EIO");
	case ENXIO: return ("ENXIO");
	case E2BIG: return ("E2BIG");
	case ENOEXEC: return ("ENOEXEC");
	case EBADF: return ("EBADF");
	case ECHILD: return ("ECHILD");
	case EAGAIN: return ("EAGAIN");
	case ENOMEM: return ("ENOMEM");
	case EACCES: return ("EACCES");
	case EFAULT: return ("EFAULT");
	case ENOTBLK: return ("ENOTBLK");
	case EBUSY: return ("EBUSY");
	case EEXIST: return ("EEXIST");
	case EXDEV: return ("EXDEV");
	case ENODEV: return ("ENODEV");
	case ENOTDIR: return ("ENOTDIR");
	case EISDIR: return ("EISDIR");
	case EINVAL: return ("EINVAL");
	case ENFILE: return ("ENFILE");
	case EMFILE: return ("EMFILE");
	case ENOTTY: return ("ENOTTY");
	case ETXTBSY: return ("ETXTBSY");
	case EFBIG: return ("EFBIG");
	case ENOSPC: return ("ENOSPC");
	case ESPIPE: return ("ESPIPE");
	case EROFS: return ("EROFS");
	case EMLINK: return ("EMLINK");
	case EPIPE: return ("EPIPE");
	case EDOM: return ("EDOM");
	case ERANGE: return ("ERANGE");
	default: return (NULL);
	}
}

struct erf erf_ok = {
    .erf_name = "NoError",
    .erf_message = "Everything is fine",
    .erf_file = "erf.c",
    .erf_line = __LINE__
};

struct erf *ERF_OK = &erf_ok;

struct erf erf_nomem = {
    .erf_errno = ENOMEM,
    .erf_name = "OutOfMemoryError",
    .erf_message = "Process failed to allocate new memory",
    .erf_file = "erf.c",
    .erf_line = __LINE__
};

struct erf *ERF_NOMEM = &erf_nomem;

struct erf *
_erf(const char *name, struct erf *cause, const char *file, uint line,
    const char *fmt, ...)
{
	struct erf *e;
	char msgbuf[256];
	size_t wrote;
	va_list ap;

	e = calloc(1, sizeof (struct erf));
	if (e == NULL)
		return (ERF_NOMEM);

	e->erf_name = name;
	e->erf_cause = cause;
	e->erf_file = file;
	e->erf_line = line;

	msgbuf[0] = '\0';
	va_start(ap, fmt);
	wrote = vsnprintf(msgbuf, sizeof (msgbuf), fmt, ap);
	va_end(ap);
	if (wrote >= sizeof (msgbuf))
		msgbuf[sizeof (msgbuf) - 1] = '\0';
	e->erf_message = strdup(msgbuf);
	if (e->erf_message == NULL) {
		free(e);
		return (ERF_NOMEM);
	}

	return (e);
}

struct erf *
_erfno(int errno, const char *file, uint line, const char *fmt, ...)
{
	struct erf *e;
	char msgbuf[256];
	size_t wrote;
	va_list ap;
	const char *macro;

	macro = errno_to_macro(errno);

	e = calloc(1, sizeof (struct erf));
	if (e == NULL)
		return (ERF_NOMEM);

	e->erf_name = macro ? macro : "SystemError";
	e->erf_file = file;
	e->erf_line = line;
	e->erf_errno = errno;

	msgbuf[0] = '\0';
	wrote = snprintf(msgbuf, sizeof (msgbuf), "Error %d (%s): %s: ",
	    errno, macro, strerror(errno));
	va_start(ap, fmt);
	wrote += vsnprintf(&msgbuf[wrote], sizeof (msgbuf) - wrote, fmt, ap);
	va_end(ap);
	if (wrote >= sizeof (msgbuf))
		msgbuf[sizeof (msgbuf) - 1] = '\0';
	e->erf_message = strdup(msgbuf);
	if (e->erf_message == NULL) {
		free(e);
		return (ERF_NOMEM);
	}

	return (e);
}

void
perf(struct erf *etop)
{
	struct erf *e;
	for (e = etop; e != NULL; e = e->erf_cause) {
		const char *prefix = "";
		if (e != etop)
			prefix = "Caused by ";
		fprintf(stderr, "%s%s: %s\n  at %s:%d\n", prefix,
		    e->erf_name, e->erf_message, e->erf_file, e->erf_line);
	}
}

void
perfexit(struct erf *etop)
{
	perf(etop);
	exit(1);
}
