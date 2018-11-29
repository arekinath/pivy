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
#include <string.h>
#include <stdarg.h>

#include "errf.h"

struct errf {
	struct errf *errf_cause;
	int errf_errno;
	char errf_name[128];
	char errf_message[256];
	const char *errf_function;
	const char *errf_file;
	uint errf_line;
};

const char *
errno_to_macro(int eno)
{
	switch (eno) {
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

struct errf errf_ok = {
    .errf_name = "NoError",
    .errf_message = "warnfx/errfx() called on a non-error",
    .errf_file = "erf.c",
    .errf_line = __LINE__
};

struct errf *ERRF_OK = NULL;

struct errf errf_nomem = {
    .errf_errno = ENOMEM,
    .errf_name = "OutOfMemoryError",
    .errf_message = "Process failed to allocate new memory",
    .errf_file = "erf.c",
    .errf_line = __LINE__
};

struct errf *ERRF_NOMEM = &errf_nomem;

const char *
errf_name(const struct errf *e)
{
	return (e->errf_name);
}

const char *
errf_message(const struct errf *e)
{
	return (e->errf_message);
}

int
errf_errno(const struct errf *e)
{
	return (e->errf_errno);
}

const char *
errf_function(const struct errf *e)
{
	return (e->errf_function);
}

const char *
errf_file(const struct errf *e)
{
	return (e->errf_file);
}

uint
errf_line(const struct errf *e)
{
	return (e->errf_line);
}

struct errf *
errf_cause(const struct errf *e)
{
	return (e->errf_cause);
}

struct errf *
_errf(const char *name, struct errf *cause, const char *func, const char *file,
    uint line, const char *fmt, ...)
{
	struct errf *e;
	size_t wrote;
	va_list ap;

	e = calloc(1, sizeof (struct errf));
	if (e == NULL)
		return (ERRF_NOMEM);

	strcpy(e->errf_name, name);
	e->errf_cause = cause;
	e->errf_file = file;
	e->errf_line = line;
	e->errf_function = func;

	va_start(ap, fmt);
	wrote = vsnprintf(e->errf_message, sizeof (e->errf_message), fmt, ap);
	va_end(ap);
	if (wrote >= sizeof (e->errf_message))
		e->errf_message[sizeof (e->errf_message) - 1] = '\0';

	return (e);
}

struct errf *
_errfno(const char *enofunc, int eno, const char *func, const char *file,
    uint line, const char *fmt, ...)
{
	struct errf *e;
	char *p;
	size_t wrote;
	va_list ap;
	const char *macro;

	macro = errno_to_macro(eno);

	e = calloc(1, sizeof (struct errf));
	if (e == NULL)
		return (ERRF_NOMEM);

	strcpy(e->errf_name, macro ? macro : "SystemError");
	e->errf_file = file;
	e->errf_line = line;
	e->errf_errno = eno;
	e->errf_function = func;

	wrote = snprintf(e->errf_message, sizeof (e->errf_message),
	    "%s returned error %d (%s): %s%s", enofunc, eno, macro,
	    strerror(eno), fmt ? ": " : "");
	if (fmt != NULL) {
		p = &e->errf_message[wrote];
		va_start(ap, fmt);
		wrote += vsnprintf(p, sizeof (e->errf_message) - wrote,
		    fmt, ap);
		va_end(ap);
	}
	if (wrote >= sizeof (e->errf_message))
		e->errf_message[sizeof (e->errf_message) - 1] = '\0';

	return (e);
}

static void
vperrf(const struct errf *etop, const char *type, const char *fmt, va_list args)
{
	const struct errf *e;
	if (etop == NULL) {
		vperrf(&errf_ok, type, fmt, args);
		return;
	}
	fprintf(stderr, "%s: %s", getprogname(), type);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	for (e = etop; e != NULL; e = e->errf_cause) {
		fprintf(stderr, "  Caused by %s: %s\n", e->errf_name,
		    e->errf_message);
		fprintf(stderr, "    in %s() at %s:%d\n", e->errf_function,
		    e->errf_file, e->errf_line);
	}
}

void
warnfx(const struct errf *etop, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vperrf(etop, "warning: ", fmt, ap);
	va_end(ap);
}

void
errfx(int status, const struct errf *etop, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vperrf(etop, "", fmt, ap);
	va_end(ap);
	exit(status);
}

boolean_t
errf_caused_by(const struct errf *e, const char *name)
{
	for (; e != NULL; e = e->errf_cause) {
		if (strcmp(name, e->errf_name) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

void
erfree(struct errf *ep)
{
	struct errf *e;
	while (ep != NULL) {
		e = ep->errf_cause;
		if (ep != ERRF_NOMEM)
			free(ep);
		ep = e;
	}
}
