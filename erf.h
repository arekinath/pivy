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

#if !defined(__sun) && !defined(USING_SPL)
typedef enum { B_FALSE = 0, B_TRUE = 1 } boolean_t;
typedef unsigned int uint;
#endif

/*
 * ERF -- annotated chained error objects for C.
 *
 * The intention is that functions which may produce an error return an erf_t*
 * where they normally would return an errno int.
 *
 * E.g.    erf_t *do_something(int arg, int *output);
 *
 * If this returns NULL (equivalent to ERF_OK) then this means "no error" (as
 * a 0 return value would normally). Otherwise it returns a pointer to an
 * erf_t describing the error that occurred.
 *
 * The erf_t is allocated from the heap (using the erf() family of function
 * macros) and belongs to the caller.
 *
 * You can chain erf_ts together as a "cause chain" to indicate more detailed
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
 * cause chain) using perf() and friends.
 */
struct erf;
typedef struct erf erf_t;

extern struct erf *ERF_OK;
extern struct erf *ERF_NOMEM;

/* Print an erf_t to stderr, prefixed by "error: " */
void perf(const struct erf *e);
/* perf() and exit(1); */
void perfexit(const struct erf *e);

/* Frees an erf_t and its cause chain. */
void erfree(struct erf *e);

/*
 * Returns B_TRUE if there is an error in the cause chain of "e" which is
 * named "name".
 */
boolean_t erf_caused_by(const struct erf *e, const char *name);

/* Accessors for basic information about the error. */
const char *erf_name(const struct erf *e);
const char *erf_message(const struct erf *e);
int erf_errno(const struct erf *e);
const char *erf_function(const struct erf *e);
const char *erf_file(const struct erf *e);
uint erf_line(const struct erf *e);
const struct erf *erf_cause(const struct erf *e);

/*
 * Basic public interface for constructing an error object.
 *
 * erf_t *erf(const char *name, erf_t *cause, const char *fmt, ...);
 *
 * Takes printf-style arguments for "fmt".
 */
#define erf(name, cause, fmt, ...)	\
    _erf(name, cause, __func__, __FILE__, __LINE__, \
    fmt __VA_OPT__(,) __VA_ARGS__)

/*
 * Turn an int errno value into an error object (includes both the macro
 * name for the errno if available and the strerror() value).
 *
 * erf_t *erfno(const char *function, int errno, const char *fmt, ...);
 */
#define erfno(func, eno, fmt, ...)	\
    _erfno(func, eno, __func__, __FILE__, __LINE__, \
    fmt __VA_OPT__(,) __VA_ARGS__)

/*
 * An example error subclass used to report an invalid argument.
 */
#define argerf(param, mustbe, butis, ...)	\
    erf("ArgumentError", NULL, \
    "Argument " param " must be " mustbe " but is " butis \
    __VA_OPT__(,) __VA_ARGS__)

/* Internal only -- used by the above macros. */
struct erf *_erf(const char *name, struct erf *cause, const char *func,
    const char *file, uint line, const char *fmt, ...);
struct erf *_erfno(const char *enofunc, int eno, const char *func,
    const char *file, uint line, const char *fmt, ...);

#endif
