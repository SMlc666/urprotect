#include "host_context_cfi_exception_bridge.h"

#include <cstdint>
#include <exception>
#include <limits>

namespace {

struct CfiTypedTestException final {
    std::uint64_t token;
};

class UnwindCleanupCounter final {
public:
    explicit UnwindCleanupCounter(std::uint32_t *counter) noexcept : counter_(counter) {}

    ~UnwindCleanupCounter() noexcept
    {
        if (counter_ != nullptr) {
            ++*counter_;
        }
    }

    UnwindCleanupCounter(const UnwindCleanupCounter &) = delete;
    UnwindCleanupCounter &operator=(const UnwindCleanupCounter &) = delete;

private:
    std::uint32_t *counter_;
};

} // namespace

extern "C" void urp_cfi_cpp_throw_from_host_callback(std::uint64_t token)
{
    throw CfiTypedTestException{token};
}

extern "C" int urp_cfi_run_cpp_exception_boundary(
    urp_cfi_target_fn target,
    const urp_host_context_v1 *host,
    const urp_launch_args_v1 *args,
    std::uintptr_t *observed_x19,
    std::uintptr_t *observed_x20,
    urp_cfi_cpp_exception_result *result)
{
    if (target == nullptr || host == nullptr || args == nullptr || result == nullptr) {
        return -1;
    }

    result->target_status = std::numeric_limits<std::int32_t>::min();
    result->caught_token = 0;
    result->register_call_attempted = 0;
    result->register_call_returned = 0;
    result->normal_target_returned = 0;
    result->caught_specific_type = 0;
    result->cleanup_count = 0;

    try {
        // This caller frame is intentionally outside the transformed target
        // and inside the typed catch boundary. Its destructor is an unwind
        // witness; it also runs on normal return, which the oracle rejects.
        UnwindCleanupCounter cleanup(&result->cleanup_count);
        result->register_call_attempted = 1;
        result->target_status = urp_cfi_invoke_with_registers(
            target,
            host,
            args,
            observed_x19,
            observed_x20);
        result->register_call_returned = 1;
        result->normal_target_returned = 1;
    } catch (const CfiTypedTestException &exception) {
        result->caught_specific_type = 1;
        result->caught_token = exception.token;
        return 1;
    }

    return 0;
}
