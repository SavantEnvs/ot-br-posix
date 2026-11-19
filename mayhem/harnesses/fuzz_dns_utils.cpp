// Fuzzes the DNS-SD name utilities (src/utils/dns_utils.cpp) that the SRP Advertising Proxy, the
// Discovery Proxy and the mDNS publishers apply to names received from Thread devices and the LAN.
#include "fuzz_common.hpp"

#include "utils/dns_utils.hpp"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FuzzInitLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    std::string name(reinterpret_cast<const char *>(aData), aSize);
    std::string a, b, c;

    otbr::DnsUtils::SplitFullDnsName(name);
    otbr::DnsUtils::SplitFullServiceName(name, a, b);
    otbr::DnsUtils::SplitFullServiceInstanceName(name, a, b, c);
    otbr::DnsUtils::SplitFullHostName(name, a, b);
    otbr::DnsUtils::UnescapeInstanceName(name);
    otbr::DnsUtils::CheckHostnameSanity(name);
    otbr::DnsUtils::CheckServiceNameSanity(name);
    return 0;
}
