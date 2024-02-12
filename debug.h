#if !defined(_DEBUG_H)
#define	_DEBUG_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <assert.h>

#include "utils.h"

#if !defined(__CPROVER)
#define __CPROVER_assume(X)	((void)(0))
#define __CPROVER_assert(X,Y)	(0)
#endif

#if defined(__sun)
#include <sys/debug.h>
#else

#undef VERIFY
#undef ASSERT

/*
 * ASSERT(ex) causes a panic or debugger entry if expression ex is not
 * true.  ASSERT() is included only for debugging, and is a no-op in
 * production kernels.  VERIFY(ex), on the other hand, behaves like
 * ASSERT and is evaluated on both debug and non-debug kernels.
 */

extern boolean_t assfail(const char *, const char *, int);
#define VERIFY(EX)	\
	((void)((EX) || assfail(#EX, __FILE__, __LINE__)), (void)(__CPROVER_assert((EX), #EX)))
#if DEBUG
#define ASSERT(EX)	\
	((void)((EX) || assfail(#EX, __FILE__, __LINE__)), (void)(__CPROVER_assert((EX), #EX)))
#else
#define ASSERT(x)  ((void)0)
#endif

/*
 * Assertion variants sensitive to the compilation data model
 */
#if defined(_LP64)
#define ASSERT64(x)     ASSERT(x)
#define ASSERT32(x)
#else
#define ASSERT64(x)
#define ASSERT32(x)     ASSERT(x)
#endif

#undef IMPLY
#undef EQUIV

/*
 * IMPLY and EQUIV are assertions of the form:
 *
 *      if (a) then (b)
 * and
 *      if (a) then (b) *AND* if (b) then (a)
 */
#if DEBUG
#define IMPLY(A, B) \
        ((void)(((!(A)) || (B)) || \
            assfail("(" #A ") implies (" #B ")", __FILE__, __LINE__)))
#define EQUIV(A, B) \
        ((void)((!!(A) == !!(B)) || \
            assfail("(" #A ") is equivalent to (" #B ")", __FILE__, __LINE__)))
#else
#define IMPLY(A, B) ((void)0)
#define EQUIV(A, B) ((void)0)
#endif

#undef VERIFY3_IMPL
#undef VERIFY3B
#undef VERIFY3S
#undef VERIFY3U
#undef VERIFY3P
#undef VERIFY0

#undef ASSERT3B
#undef ASSERT3S
#undef ASSERT3U
#undef ASSERT3P
#undef ASSERT0

/*
 * ASSERT3() behaves like ASSERT() except that it is an explicit conditional,
 * and prints out the values of the left and right hand expressions as part of
 * the panic message to ease debugging.  The three variants imply the type
 * of their arguments.  ASSERT3S() is for signed data types, ASSERT3U() is
 * for unsigned, and ASSERT3P() is for pointers.  The VERIFY3*() macros
 * have the same relationship as above.
 */
extern void assfail3(const char *, uintmax_t, const char *, uintmax_t,
    const char *, int);
#define VERIFY3_IMPL(LEFT, OP, RIGHT, TYPE) do { \
        const TYPE __left = (TYPE)(LEFT); \
        const TYPE __right = (TYPE)(RIGHT); \
        if (!(__left OP __right)) \
                assfail3(#LEFT " " #OP " " #RIGHT, \
                        (uintmax_t)__left, #OP, (uintmax_t)__right, \
                        __FILE__, __LINE__); \
} while (0)

#define VERIFY3B(x, y, z)       VERIFY3_IMPL(x, y, z, boolean_t)
#define VERIFY3S(x, y, z)       VERIFY3_IMPL(x, y, z, int64_t)
#define VERIFY3U(x, y, z)       VERIFY3_IMPL(x, y, z, uint64_t)
#define VERIFY3P(x, y, z)       VERIFY3_IMPL(x, y, z, uintptr_t)
#define VERIFY0(x)              VERIFY3_IMPL(x, ==, 0, uintmax_t)

#if DEBUG
#define ASSERT3B(x, y, z)       VERIFY3_IMPL(x, y, z, boolean_t)
#define ASSERT3S(x, y, z)       VERIFY3_IMPL(x, y, z, int64_t)
#define ASSERT3U(x, y, z)       VERIFY3_IMPL(x, y, z, uint64_t)
#define ASSERT3P(x, y, z)       VERIFY3_IMPL(x, y, z, uintptr_t)
#define ASSERT0(x)              VERIFY3_IMPL(x, ==, 0, uintmax_t)
#else
#define ASSERT3B(x, y, z)       ((void)0)
#define ASSERT3S(x, y, z)       ((void)0)
#define ASSERT3U(x, y, z)       ((void)0)
#define ASSERT3P(x, y, z)       ((void)0)
#define ASSERT0(x)              ((void)0)
#endif

#undef CTASSERT
#undef _CTASSERT
#undef __CTASSERT

/*
 * Compile-time assertion. The condition 'x' must be constant.
 */
#define CTASSERT(x)             _CTASSERT(x, __LINE__)
#define _CTASSERT(x, y)         __CTASSERT(x, y)
#define __CTASSERT(x, y) \
        typedef char __compile_time_assertion__ ## y [(x) ? 1 : -1] __unused

#ifdef  _KERNEL

extern void abort_sequence_enter(char *);
extern void debug_enter(char *);

#endif  /* _KERNEL */

#if defined(DEBUG) && !defined(__sun)
/* CSTYLED */
#define STATIC
#else
/* CSTYLED */
#define STATIC static
#endif

#endif /* defined(__sun) */

#ifdef  __cplusplus
}
#endif

#undef VERIFYN

#if defined(__CPROVER)
#define	VERIFYN(EX) do { \
	__CPROVER_assume((EX) != NULL); \
	((void)(((EX) != NULL) || assfail(#EX " non-NULL", __FILE__, __LINE__))); \
	} while (0)
#else
#define	VERIFYN(EX)	((void)(((EX) != NULL) || assfail(#EX " non-NULL", __FILE__, __LINE__)))
#endif

#if defined(__CPROVER)
/*
 * CBMC has special knowledge of memcpy/memset, so change bcopy/bzero into those
 * when we're running under the prover.
 */
#define bcopy(SRC, DST, SIZE)		memcpy((DST), (SRC), (SIZE))
#define bzero(DST, SIZE)		memset((DST), 0, (SIZE))
#define explicit_bzero(DST, SIZE)	memset((DST), 0, (SIZE))
#endif

#endif
