#include "host_context_threaded_tls_trace.h"

#include <stdio.h>

static int expect_valid(const char *trace, const char *mode)
{
    return urp_validate_threaded_tls_trace(trace, mode) == URP_THREADED_TLS_TRACE_OK ? 0 : 1;
}

static int expect_result(const char *trace, const char *mode, int expected)
{
    return urp_validate_threaded_tls_trace(trace, mode) == expected ? 0 : 1;
}

int main(void)
{
    const char *automatic =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "worker-start tls=4660 zero=0\n"
        "entry-tls-isolated zero=17185\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "destructor\n";
    const char *explicit_trace =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "entry-tls-isolated zero=17185\n"
        "worker-start tls=4660 zero=0\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "entry-joined\n"
        "destructor\n";
    const char *early_join =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "entry-joined\n"
        "entry-tls-isolated zero=17185\n"
        "worker-start tls=4660 zero=0\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "destructor\n";
    const char *missing_marker =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "worker-start tls=4660 zero=0\n"
        "entry-tls-isolated zero=17185\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n";
    const char *late_join =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "worker-start tls=4660 zero=0\n"
        "entry-tls-isolated zero=17185\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "entry-joined\n"
        "destructor\n";
    const char *isolated_first =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "entry-tls-isolated zero=17185\n"
        "worker-start tls=4660 zero=0\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "destructor\n";
    const char *unknown_text =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "unexpected-marker text\n"
        "entry-tls-isolated zero=17185\n"
        "worker-start tls=4660 zero=0\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "destructor\n";
    const char *duplicate_lifecycle =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "entry-tls-isolated zero=17185\n"
        "worker-start tls=4660 zero=0\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "tls-teardown\n"
        "destructor\n";
    const char *trailing_text =
        "constructor\n"
        "entry-tls data=4660 zero=0\n"
        "entry\n"
        "entry-tls-isolated zero=17185\n"
        "worker-start tls=4660 zero=0\n"
        "worker-complete tls=4660 zero=22136\n"
        "tls-teardown\n"
        "destructor\n"
        "unexpected trailing text\n";
    if (expect_valid(automatic, "automatic") != 0
        || expect_valid(automatic, "failure") != 0
        || expect_valid(explicit_trace, "explicit") != 0
        || expect_result(early_join, "explicit", URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN) != 0
        || expect_result(late_join, "automatic", URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN) != 0
        || expect_result(late_join, "failure", URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN) != 0
        || expect_result(missing_marker, "automatic", URP_THREADED_TLS_TRACE_MISSING_MARKER) != 0
        || expect_result(unknown_text, "automatic", URP_THREADED_TLS_TRACE_UNEXPECTED_TEXT) != 0
        || expect_result(duplicate_lifecycle, "automatic", URP_THREADED_TLS_TRACE_DUPLICATE_MARKER) != 0
        || expect_result(trailing_text, "automatic", URP_THREADED_TLS_TRACE_TRAILING_DATA) != 0)
        return 1;

    /* Keep the reusable helper's pair-order boundary explicit in the test. */
    if (expect_valid(isolated_first, "automatic") != 0) return 1;

    puts("threaded TLS trace parser: PASS");
    return 0;
}
