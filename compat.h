/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2019, Joyent Inc
 */

#if !defined(_PIVY_COMPAT_H)
#define _PIVY_COMPAT_H

#if defined(HAVE_BOUNDED_ATTR)
#define __bounded(_what, ...) __attribute__((__bounded__(_what, __VA_ARG__)))
#else
#define __bounded(_what, ...)
#endif

#if defined(__APPLE__)
void *reallocarray(void *, size_t, size_t);
void explicit_bzero(void *, size_t);
#endif

#endif /* _PIVY_COMPAT_H */
