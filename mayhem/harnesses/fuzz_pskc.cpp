// Fuzzes the PSKc derivation (otbr::Psk::Pskc::ComputePskc, src/utils/pskc.cpp) with a passphrase,
// extended PAN ID and network name as the web GUI's form handler passes them (wpan_service.cpp, no
// length clamp on the network name) and as the `pskc` CLI tool does after its own argument checks.
// Input: <passphrase>\0<network name>\0<8-byte ext PAN ID>
// Throughput is low (about 10-20 exec/s) by design: every call runs upstream's PBKDF2 with
// OT_ITERATION_COUNTS = 16384 AES-CMAC rounds (src/utils/pskc.hpp:40, pskc.cpp:109). That cost is the code
// under test, not harness overhead, so the harness does not cap the inputs or the iteration count.
#include "fuzz_common.hpp"

#include "utils/pskc.hpp"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FuzzInitLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    std::string in(reinterpret_cast<const char *>(aData), aSize);
    size_t      p1 = in.find('\0');
    size_t      p2;

    if (p1 == std::string::npos)
    {
        return -1;
    }
    p2 = in.find('\0', p1 + 1);
    if (p2 == std::string::npos)
    {
        return -1;
    }

    std::string passphrase = in.substr(0, p1);
    std::string name       = in.substr(p1 + 1, p2 - p1 - 1);
    std::string rest       = in.substr(p2 + 1);
    uint8_t     extPanId[OT_EXTENDED_PAN_ID_LENGTH] = {0};

    // Both callers bound the passphrase (tool: <= 255 bytes; web: OpenThread's PSKc limit), and each
    // call runs 16384 CMAC rounds over it: keep it in that documented range.
    if (passphrase.size() > OT_PASSPHRASE_MAX_LENGTH)
    {
        return -1;
    }
    memcpy(extPanId, rest.data(), rest.size() < sizeof(extPanId) ? rest.size() : sizeof(extPanId));

    otbr::Psk::Pskc pskc;
    pskc.ComputePskc(extPanId, name.c_str(), passphrase.c_str());
    return 0;
}
