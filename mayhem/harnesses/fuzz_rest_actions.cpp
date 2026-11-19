// Fuzzes the REST API's action queue (POST /api/actions body -> rest::ActionsList, src/rest/actions_list.cpp
// and src/rest/actions/*.cpp: network diagnostic, add thread device, energy scan, discover network, reset
// diagnostic counters) on a real OpenThread instance over OpenThread's fake platform, as upstream's
// tests/gtest/test_rest.cpp sets it up. The input is the HTTP request body; the harness performs the same
// steps as RestWebServer::ApiActionsPostHandler, then lets the queued actions run on the main loop.
//
// State kept across inputs on purpose: the OpenThread instance (a single-node leader, created once,
// never reconfigured by an input) and the REST Services object. Every action an input queued is deleted
// before the next input (ActionsList::DeleteAllActions), so the queue starts empty each time, and the main
// loop then runs until the OpenThread commissioner an add-device or energy-scan action started is stopped
// again (CommissionerManager::Process stops it lazily). What still carries over is the leader's commissioner
// session ID and network data version, which each such input increments; no action reads them back.
#include "fuzz_common.hpp"

#include <memory>
#include <vector>

#include <cJSON.h>

#include <openthread/commissioner.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>
#include <openthread/ip6.h>
#include <openthread/thread.h>

#include "common/mainloop.hpp"
#include "common/mainloop_manager.hpp"
#include "host/rcp_host.hpp"
#include "rest/actions_list.hpp"
#include "rest/services.hpp"
#include "fake_platform.hpp"

using namespace otbr;
using namespace otbr::rest;

// Created once and never destroyed: static destructors would run after MainloopManager's.
static Host::RcpHost *sHost;
static Services      *sServices;
static MainloopContext                sMainloop;

static void Pump(int aIterations)
{
    for (int i = 0; i < aIterations; i++)
    {
        sMainloop.mMaxFd   = -1;
        sMainloop.mTimeout = {0, 0};
        FD_ZERO(&sMainloop.mReadFdSet);
        FD_ZERO(&sMainloop.mWriteFdSet);
        FD_ZERO(&sMainloop.mErrorFdSet);
        MainloopManager::GetInstance().Update(sMainloop);
        MainloopManager::GetInstance().Process(sMainloop);
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FuzzInitLogging();

    sHost = new Host::RcpHost("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "",
                              /* aDryRun */ false, /* aEnableAutoAttach */ false);
    sHost->Init();

    otInstance              *instance = ot::FakePlatform::CurrentInstance();
    otOperationalDataset     dataset;
    otOperationalDatasetTlvs tlvs;

    otDatasetCreateNewNetwork(instance, &dataset);
    otDatasetConvertToTlvs(&dataset, &tlvs);
    otDatasetSetActiveTlvs(instance, &tlvs);
    otIp6SetEnabled(instance, true);
    otThreadSetEnabled(instance, true);
    for (int i = 0; i < 20000 && sHost->GetDeviceRole() != OT_DEVICE_ROLE_LEADER; i++)
    {
        Pump(1);
    }

    sServices = new Services();
    sServices->Init(instance);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    ActionsList &actions = sServices->GetActionsList();
    std::string  body(reinterpret_cast<const char *>(aData), aSize); // the server parses body.c_str()
    cJSON       *root = cJSON_Parse(body.c_str());
    cJSON       *dataArray;
    bool         valid = true;
    uint32_t     queueMax;

    if (root == nullptr)
    {
        return 0;
    }

    dataArray = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (dataArray != nullptr && cJSON_IsArray(dataArray))
    {
        for (int i = 0; i < cJSON_GetArraySize(dataArray) && valid; i++)
        {
            valid = actions.ValidateRequest(cJSON_GetArrayItem(dataArray, i));
        }

        actions.GetPendingOrActive(queueMax);
        queueMax -= actions.GetMaxCollectionSize();
        if (valid && queueMax >= static_cast<uint32_t>(cJSON_GetArraySize(dataArray)))
        {
            for (int i = 0; i < cJSON_GetArraySize(dataArray); i++)
            {
                std::string uuid(UUID_STR_LEN, '\0');
                if (actions.CreateAction(cJSON_GetArrayItem(dataArray, i), uuid) == OT_ERROR_NONE)
                {
                    cJSON *json = actions.JsonifyAction(uuid);
                    cJSON_Delete(json);
                }
            }

            for (int round = 0; round < 4; round++)
            {
                Pump(5);
                actions.UpdateAllActions();
            }
        }
    }

    cJSON_Delete(root);
    actions.DeleteAllActions();
    Pump(1);
    for (int i = 0; i < 1000 && otCommissionerGetState(ot::FakePlatform::CurrentInstance()) !=
                                    OT_COMMISSIONER_STATE_DISABLED;
         i++)
    {
        Pump(1);
    }
    return 0;
}
