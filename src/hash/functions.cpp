#include <cstdint>
#include <functional>
#include <span>
#include <vector>

extern "C"
{
#include "lib_ecc_config.h"
#include "libsig.h"
}

namespace feistelizer 
{
    const std::function sha256 = [](const std::span<const uint8_t> arg) {
        sha256_context ctx;
        std::vector<uint8_t> ret(SHA256_DIGEST_SIZE);
        sha256_init(&ctx);
        sha256_update(&ctx, arg.data(), arg.size_bytes());
        sha256_final(&ctx, ret.data());
        return ret;
    };
};