#include "host_context_threaded_tls_trace.h"

#include <stddef.h>
#include <string.h>

enum marker_index {
    MARKER_CONSTRUCTOR = 0,
    MARKER_ENTRY_TLS,
    MARKER_ENTRY,
    MARKER_ENTRY_TLS_ISOLATED,
    MARKER_WORKER_START,
    MARKER_WORKER_COMPLETE,
    MARKER_TLS_TEARDOWN,
    MARKER_ENTRY_JOINED,
    MARKER_DESTRUCTOR,
    MARKER_COUNT,
};

static const char *const markers[MARKER_COUNT] = {
    "constructor\n",
    "entry-tls data=4660 zero=0\n",
    "entry\n",
    "entry-tls-isolated zero=17185\n",
    "worker-start tls=4660 zero=0\n",
    "worker-complete tls=4660 zero=22136\n",
    "tls-teardown\n",
    "entry-joined\n",
    "destructor\n",
};

static int marker_at_cursor(const char *cursor, size_t *found_index)
{
    if (*cursor == '\0') return 0;
    for (size_t index = 0U; index < MARKER_COUNT; ++index) {
        size_t length = strlen(markers[index]);
        if (strncmp(cursor, markers[index], length) == 0) {
            *found_index = index;
            return 1;
        }
    }
    return 0;
}

static int unexpected_at_cursor(
    const char *cursor,
    const unsigned char *seen,
    int trailing)
{
    size_t found_index = 0U;
    if (*cursor == '\0') return URP_THREADED_TLS_TRACE_MISSING_MARKER;
    if (!marker_at_cursor(cursor, &found_index)) {
        return trailing
            ? URP_THREADED_TLS_TRACE_TRAILING_DATA
            : URP_THREADED_TLS_TRACE_UNEXPECTED_TEXT;
    }
    if (seen[found_index] != 0U) return URP_THREADED_TLS_TRACE_DUPLICATE_MARKER;
    if (found_index == MARKER_ENTRY_JOINED) return URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN;
    return URP_THREADED_TLS_TRACE_ORDER_ERROR;
}

static int consume_expected(
    const char **cursor,
    size_t expected_index,
    unsigned char *seen)
{
    size_t found_index = 0U;
    if (**cursor == '\0') return URP_THREADED_TLS_TRACE_MISSING_MARKER;
    if (!marker_at_cursor(*cursor, &found_index))
        return URP_THREADED_TLS_TRACE_UNEXPECTED_TEXT;
    if (seen[found_index] != 0U) return URP_THREADED_TLS_TRACE_DUPLICATE_MARKER;
    if (found_index != expected_index) {
        if (found_index == MARKER_ENTRY_JOINED)
            return URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN;
        return URP_THREADED_TLS_TRACE_ORDER_ERROR;
    }
    *cursor += strlen(markers[expected_index]);
    seen[expected_index] = 1U;
    return URP_THREADED_TLS_TRACE_OK;
}

static int consume_pair_start(
    const char **cursor,
    size_t first_index,
    size_t second_index,
    unsigned char *seen)
{
    size_t found_index = 0U;
    if (**cursor == '\0') return URP_THREADED_TLS_TRACE_MISSING_MARKER;
    if (!marker_at_cursor(*cursor, &found_index))
        return URP_THREADED_TLS_TRACE_UNEXPECTED_TEXT;
    if (seen[found_index] != 0U) return URP_THREADED_TLS_TRACE_DUPLICATE_MARKER;
    if (found_index == MARKER_ENTRY_JOINED)
        return URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN;
    if (found_index != first_index && found_index != second_index)
        return URP_THREADED_TLS_TRACE_ORDER_ERROR;
    *cursor += strlen(markers[found_index]);
    seen[found_index] = 1U;
    return URP_THREADED_TLS_TRACE_OK;
}

int urp_validate_threaded_tls_trace(const char *output, const char *mode)
{
    if (output == NULL || mode == NULL) return URP_THREADED_TLS_TRACE_UNKNOWN_MODE;
    if (strcmp(mode, "automatic") != 0 && strcmp(mode, "explicit") != 0
        && strcmp(mode, "failure") != 0)
        return URP_THREADED_TLS_TRACE_UNKNOWN_MODE;

    unsigned char seen[MARKER_COUNT] = { 0U };
    const char *cursor = output;
    const size_t prefix[] = { MARKER_CONSTRUCTOR, MARKER_ENTRY_TLS, MARKER_ENTRY };
    for (size_t index = 0U; index < sizeof(prefix) / sizeof(prefix[0]); ++index) {
        int result = consume_expected(&cursor, prefix[index], seen);
        if (result != URP_THREADED_TLS_TRACE_OK) return result;
    }

    /* Only this pair is unordered. Both markers must arrive before completion. */
    int result = consume_pair_start(
        &cursor, MARKER_ENTRY_TLS_ISOLATED, MARKER_WORKER_START, seen);
    if (result != URP_THREADED_TLS_TRACE_OK) return result;
    size_t other_index = seen[MARKER_ENTRY_TLS_ISOLATED] != 0U
        ? MARKER_WORKER_START : MARKER_ENTRY_TLS_ISOLATED;
    result = consume_expected(&cursor, other_index, seen);
    if (result != URP_THREADED_TLS_TRACE_OK) return result;

    const size_t automatic_suffix[] = {
        MARKER_WORKER_COMPLETE, MARKER_TLS_TEARDOWN, MARKER_DESTRUCTOR,
    };
    const size_t explicit_suffix[] = {
        MARKER_WORKER_COMPLETE, MARKER_TLS_TEARDOWN, MARKER_ENTRY_JOINED, MARKER_DESTRUCTOR,
    };
    const size_t *suffix = automatic_suffix;
    size_t suffix_count = sizeof(automatic_suffix) / sizeof(automatic_suffix[0]);
    if (strcmp(mode, "explicit") == 0) {
        suffix = explicit_suffix;
        suffix_count = sizeof(explicit_suffix) / sizeof(explicit_suffix[0]);
    }
    for (size_t index = 0U; index < suffix_count; ++index) {
        result = consume_expected(&cursor, suffix[index], seen);
        if (result != URP_THREADED_TLS_TRACE_OK) return result;
    }

    if (*cursor != '\0') {
        return unexpected_at_cursor(cursor, seen, 1);
    }
    return URP_THREADED_TLS_TRACE_OK;
}
