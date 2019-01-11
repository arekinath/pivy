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

#include "erf.h"

struct erf {
	struct erf *erf_cause;
	int erf_errno;
	char erf_name[128];
	char erf_message[256];
	const char *erf_function;
	const char *erf_file;
	uint erf_line;
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

struct erf erf_ok = {
    .erf_name = "NoError",
    .erf_message = "perf() called on a non-error",
    .erf_file = "erf.c",
    .erf_line = __LINE__
};

struct erf *ERF_OK = NULL;

struct erf erf_nomem = {
    .erf_errno = ENOMEM,
    .erf_name = "OutOfMemoryError",
    .erf_message = "Process failed to allocate new memory",
    .erf_file = "erf.c",
    .erf_line = __LINE__
};

struct erf *ERF_NOMEM = &erf_nomem;

const char *
erf_name(const struct erf *e)
{
	return (e->erf_name);
}

const char *
erf_message(const struct erf *e)
{
	return (e->erf_message);
}

int
erf_errno(const struct erf *e)
{
	return (e->erf_errno);
}

const char *
erf_function(const struct erf *e)
{
	return (e->erf_function);
}

const char *
erf_file(const struct erf *e)
{
	return (e->erf_file);
}

uint
erf_line(const struct erf *e)
{
	return (e->erf_line);
}

const struct erf *
erf_cause(const struct erf *e)
{
	return (e->erf_cause);
}

struct erf *
_erf(const char *name, struct erf *cause, const char *func, const char *file,
    uint line, const char *fmt, ...)
{
	struct erf *e;
	size_t wrote;
	va_list ap;

	e = calloc(1, sizeof (struct erf));
	if (e == NULL)
		return (ERF_NOMEM);

	strcpy(e->erf_name, name);
	e->erf_cause = cause;
	e->erf_file = file;
	e->erf_line = line;
	e->erf_function = func;

	va_start(ap, fmt);
	wrote = vsnprintf(e->erf_message, sizeof (e->erf_message), fmt, ap);
	va_end(ap);
	if (wrote >= sizeof (e->erf_message))
		e->erf_message[sizeof (e->erf_message) - 1] = '\0';

	return (e);
}

struct erf *
_erfno(const char *enofunc, int eno, const char *func ,const char *file,
    uint line, const char *fmt, ...)
{
	struct erf *e;
	char *p;
	size_t wrote;
	va_list ap;
	const char *macro;

	macro = errno_to_macro(eno);

	e = calloc(1, sizeof (struct erf));
	if (e == NULL)
		return (ERF_NOMEM);

	strcpy(e->erf_name, macro ? macro : "SystemError");
	e->erf_file = file;
	e->erf_line = line;
	e->erf_errno = eno;
	e->erf_function = func;

	wrote = snprintf(e->erf_message, sizeof (e->erf_message),
	    "%s returned error %d (%s): %s: ", enofunc, eno, macro,
	    strerror(eno));
	p = &e->erf_message[wrote];
	va_start(ap, fmt);
	wrote += vsnprintf(p, sizeof (e->erf_message) - wrote, fmt, ap);
	va_end(ap);
	if (wrote >= sizeof (e->erf_message))
		e->erf_message[sizeof (e->erf_message) - 1] = '\0';

	return (e);
}

void
perf(const struct erf *etop)
{
	const struct erf *e;
	const char *prefix = "error: ";
	if (etop == NULL) {
		perf(&erf_ok);
		return;
	}
	for (e = etop; e != NULL; e = e->erf_cause) {
		fprintf(stderr, "%s%s: %s\n    in %s() at %s:%d\n", prefix,
		    e->erf_name, e->erf_message, e->erf_function, e->erf_file,
		    e->erf_line);
		prefix = "  Caused by ";
	}
}

void
perfexit(const struct erf *etop)
{
	perf(etop);
	exit(1);
}

boolean_t
erf_caused_by(const struct erf *e, const char *name)
{
	for (; e != NULL; e = e->erf_cause) {
		if (strcmp(name, e->erf_name) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

void
erfree(struct erf *ep)
{
	struct erf *e;
	while (ep != NULL) {
		e = ep->erf_cause;
		if (ep != ERF_NOMEM)
			free(ep);
		ep = e;
	}
}
