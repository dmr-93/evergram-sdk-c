#ifndef EVERGRAM_EXPORT_H
#define EVERGRAM_EXPORT_H

/*
 * ABI macros. Kept in a standalone header so both status.h and types.h can use
 * them without depending on each other.
 */

/* printf-style format checking where the compiler supports it. */
#if defined(__GNUC__) || defined(__clang__)
#define EVERGRAM_PRINTF(fmt_index, first_arg) __attribute__((format(printf, fmt_index, first_arg)))
#else
#define EVERGRAM_PRINTF(fmt_index, first_arg)
#endif

/*
 * Marks a declaration as part of the public ABI. The library is built with
 * -fvisibility=hidden, so anything without this attribute stays internal to
 * the shared object.
 */
#if defined(__GNUC__) || defined(__clang__)
#define EVERGRAM_API __attribute__((visibility("default")))
#else
#define EVERGRAM_API
#endif

#endif /* EVERGRAM_EXPORT_H */
