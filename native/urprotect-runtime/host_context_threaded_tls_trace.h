#ifndef URP_HOST_CONTEXT_THREADED_TLS_TRACE_H
#define URP_HOST_CONTEXT_THREADED_TLS_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

enum urp_threaded_tls_trace_result {
    URP_THREADED_TLS_TRACE_OK = 0,
    URP_THREADED_TLS_TRACE_MISSING_MARKER = 1,
    URP_THREADED_TLS_TRACE_ORDER_ERROR = 2,
    URP_THREADED_TLS_TRACE_FORBIDDEN_ENTRY_JOIN = 3,
    URP_THREADED_TLS_TRACE_UNKNOWN_MODE = 4,
    URP_THREADED_TLS_TRACE_UNEXPECTED_TEXT = 5,
    URP_THREADED_TLS_TRACE_DUPLICATE_MARKER = 6,
    URP_THREADED_TLS_TRACE_TRAILING_DATA = 7,
};

int urp_validate_threaded_tls_trace(const char *output, const char *mode);

#ifdef __cplusplus
}
#endif

#endif
