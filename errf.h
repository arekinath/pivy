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

#include "utils.h"

/*
 * ERF -- annotated chained error objects for C.
 *
 * The intention is that functions which may produce an error return an errf_t*
 * where they normally would return an errno int.
 *
 * E.g.    errf_t *do_something(int arg, int *output);
 *
 * If this returns NULL (equivalent to ERRF_OK) then this means "no error" (as
 * a 0 return value would normally). Otherwise it returns a pointer to an
 * errf_t describing the error that occurred.
 *
 * The errf_t is allocated from the heap (using the errf() family of function
 * macros) and belongs to the caller.
 *
 * You can chain errf_ts together as a "cause chain" to indicate more detailed
 * information about the error. This is useful when high up a chain of
 * abstraction in order to understand the context where the error happened
 * For example, let's say a database couldn't answer your query because while
 * it was trying to get data from table X it tried to open file Y and failed due
 * to some errno. We could end up with the following cause chain:
 *
 *   QueryError: database was not able to handle query: "SELECT ..."
 *     Caused by: TableOpenError: failed to open index for table "foobar"
 *     Caused by: SystemError: open("xxy.idx") returned error 1 (EPERM):
 *                             Permission denied.
 *
 * This results in clearer bug reports for developers and output for users with
 * specific information as well as general information to figure out what's
 * going on.
 *
 * Error objects can be nicely formatted to the console (including their
 * cause chain) using perrf() and friends.
 */
struct errf;
typedef struct errf errf_t;

/* Define this here since it's pretty useful for things that return errf_t */
#define MUST_CHECK  __attribute__((warn_unused_result))

#define ERRF_OK     NULL
extern struct errf *ERRF_NOMEM;

/* Print an errf_t and message to stderr, like warnx/warn */
void warnfx(const struct errf *e, const char *fmt, ...);
/* Print an errf_t and message to stderr and exit, like errx/err */
void errfx(int status, const struct errf *e, const char *fmt, ...);

/* Frees an errf_t and its cause chain. */
void errf_free(struct errf *e);

/*
 * Returns B_TRUE if there is an error in the cause chain of "e" which is
 * named "name".
 */
boolean_t errf_caused_by(const struct errf *e, const char *name);

/* Accessors for basic information about the error. */
const char *errf_name(const struct errf *e);
const char *errf_message(const struct errf *e);
int errf_errno(const struct errf *e);
const char *errf_function(const struct errf *e);
const char *errf_file(const struct errf *e);
uint errf_line(const struct errf *e);
struct errf *errf_cause(const struct errf *e);

#ifndef LINT

/*
 * Basic public interface for constructing an error object.
 *
 * errf_t *errf(const char *name, errf_t *cause, const char *fmt, ...);
 *
 * Takes printf-style arguments for "fmt".
 */
#define errf(name, cause, fmt, ...)	\
    _errf(name, cause, __func__, __FILE__, __LINE__, \
    fmt, ##__VA_ARGS__)

/*
 * Turn an int errno value into an error object (includes both the macro
 * name for the errno if available and the strerror() value).
 *
 * errf_t *errfno(const char *function, int errno, const char *fmt, ...);
 */
#define errfno(func, eno, fmt, ...)	\
    _errfno(func, eno, __func__, __FILE__, __LINE__, \
    fmt, ##__VA_ARGS__)

/*
 * An example error subclass used to report an invalid argument.
 */
#define argerrf(param, mustbe, butis, ...)	\
    errf("ArgumentError", NULL, \
    "Argument " param " must be " mustbe " but is " butis, \
    ##__VA_ARGS__)

#define	funcerrf(cause, fmt, ...)	\
    errf(__func__, cause, fmt , ##__VA_ARGS__)
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))

#else

/* smatch and similar don't support varargs macros */
#define	errf(name, cause, fmt, ...)	\
    _errf(name, cause, __func__, __FILE__, __LINE__, fmt)

#endif

/* Internal only -- used by the above macros. */
struct errf *_errf(const char *name, struct errf *cause, const char *func,
    const char *file, uint line, const char *fmt, ...);
struct errf *_errfno(const char *enofunc, int eno, const char *func,
    const char *file, uint line, const char *fmt, ...);

#endif
