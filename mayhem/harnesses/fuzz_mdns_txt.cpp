// Fuzzes the DNS TXT RDATA codec (Mdns::Publisher::DecodeTxtData / EncodeTxtData, src/mdns/mdns.cpp),
// which decodes TXT records of services discovered on the LAN (TREL peers, discovery proxy, border agent).
#include "fuzz_common.hpp"

#include <vector>

#include "mdns/mdns.hpp"

using otbr::Mdns::Publisher;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FuzzInitLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    Publisher::TxtList list;
    Publisher::TxtData encoded;

    // DecodeTxtData takes a uint16_t length: TXT RDATA can never exceed 65535 bytes (RFC 1035 RDLENGTH).
    if (aSize > UINT16_MAX)
    {
        return -1;
    }

    if (Publisher::DecodeTxtData(list, aData, static_cast<uint16_t>(aSize)) == OTBR_ERROR_NONE)
    {
        if (Publisher::EncodeTxtData(list, encoded) == OTBR_ERROR_NONE && encoded.size() <= UINT16_MAX)
        {
            Publisher::TxtList again;
            Publisher::DecodeTxtData(again, encoded.data(), static_cast<uint16_t>(encoded.size()));
        }
    }
    return 0;
}
