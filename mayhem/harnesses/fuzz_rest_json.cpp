// Fuzzes the REST API's JSON request-body parsers (src/rest/json.cpp): the bodies of
// PUT /node/dataset/{active,pending}, POST /node/commissioner/joiner, the ePSKc activation request and
// JSON string bodies, round-tripping what parses back to JSON as the server does in its responses.
#include "fuzz_common.hpp"

#include <vector>

#include <openthread/dataset.h>
#include <openthread/joiner.h>

#include "rest/json.hpp"

using namespace otbr::rest;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FuzzInitLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    if (aSize < 1)
    {
        return -1;
    }

    uint8_t     selector = aData[0];
    std::string body(reinterpret_cast<const char *>(aData + 1), aSize - 1);

    switch (selector % 6)
    {
    case 0:
    {
        otOperationalDataset dataset;
        memset(&dataset, 0, sizeof(dataset));
        if (Json::JsonActiveDatasetString2Dataset(body, dataset))
        {
            Json::ActiveDataset2JsonString(dataset);
        }
        break;
    }
    case 1:
    {
        otOperationalDataset dataset;
        memset(&dataset, 0, sizeof(dataset));
        if (Json::JsonPendingDatasetString2Dataset(body, dataset))
        {
            Json::PendingDataset2JsonString(dataset);
        }
        break;
    }
    case 2:
    {
        otJoinerInfo joiner;
        memset(&joiner, 0, sizeof(joiner));
        if (Json::JsonJoinerInfoString2JoinerInfo(body, joiner))
        {
            std::vector<otJoinerInfo> table{joiner};
            Json::JoinerInfo2JsonString(joiner);
            Json::JoinerTable2JsonString(table);
        }
        break;
    }
    case 3:
    {
        uint32_t lifetime = 0;
        uint16_t port     = 0;
        Json::JsonEpskcActivateParams(body, lifetime, port);
        break;
    }
    case 4:
    {
        std::string out;
        if (Json::JsonString2String(body, out))
        {
            Json::String2JsonString(out);
        }
        break;
    }
    default:
    {
        // The discerner string as it arrives in a joiner request ("<value>/<length>"); the function
        // edits it in place, so give it a NUL-terminated writable copy.
        std::vector<char> buf(body.begin(), body.end());
        otJoinerDiscerner discerner;
        buf.push_back('\0');
        memset(&discerner, 0, sizeof(discerner));
        Json::StringDiscerner2Discerner(buf.data(), discerner);
        break;
    }
    }
    return 0;
}
