#include <cstdint>
#include <iostream>
#include <string>

namespace {
std::string fixture_value() {
    constexpr std::uint64_t value = 0x0123456789abcdefULL;
    return "checksum=" + std::to_string(value ^ (value >> 17));
}
}

int main() {
    std::cout << "urprotect-fixture:cxx\n" << fixture_value() << '\n';
    return 0;
}
