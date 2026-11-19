// Fuzzes the border router's NCP host (src/host/ncp_host.cpp, src/host/ncp_spinel.cpp: HandleReceivedFrame,
// HandleValueIs/Inserted/Removed, the IPv6 address/multicast tables, UDP forward stream, dataset and
// DNS-SD properties) with spinel frames arriving from the network co-processor. The co-processor link is
// upstream's own test double (FakeNcpSpinelInterface in tests/gtest/test_ncp_host_api.cpp, reproduced
// below): it answers the reset/version/capability handshake so the real ot::Spinel::SpinelDriver and
// NcpHost initialise, and the harness then delivers the input's frames through the driver's receive path.
//
// Input: a sequence of frames, each <len: 2 bytes, little-endian><frame bytes>, so frames past spinel's
// 1300-byte SPINEL_FRAME_MAX_SIZE reach RxFrameBuffer's own overflow handling. Every input gets a freshly initialised
// spinel driver and NcpHost (both torn down afterwards), so no state carries over between inputs.
// NcpHost::Deinit does not close the CLI daemon's listen socket, so the harness closes the file descriptors
// opened during that input (otherwise descriptors pass FD_SETSIZE after ~1000 inputs). The snapshot is taken
// per input, not once at LLVMFuzzerInitialize: descriptors the fuzzer opens later (libFuzzer's -fork mode and
// Mayhem's driver do) must stay open, and closing them left libFuzzer running with no coverage at all.
#include "fuzz_common.hpp"

#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

#include <set>

#include <openthread/openthread-system.h>
#include <openthread/platform/misc.h>

#include "common/mainloop.hpp"
#include "common/mainloop_manager.hpp"
#include "host/ncp_host.hpp"
#include "lib/spinel/coprocessor_type.h"
#include "lib/spinel/spinel.h"
#include "lib/spinel/spinel_driver.hpp"
#include "lib/spinel/spinel_interface.hpp"

extern CoprocessorType sCoprocessorType;

void otPlatReset(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);
}

namespace {

class FakeNcpSpinelInterface : public ot::Spinel::SpinelInterface
{
public:
    otError Init(ReceiveFrameCallback aCallback, void *aCallbackContext, RxFrameBuffer &aFrameBuffer) override
    {
        mCallback        = aCallback;
        mCallbackContext = aCallbackContext;
        mFrameBuffer     = &aFrameBuffer;
        return OT_ERROR_NONE;
    }

    void Deinit(void) override {}

    otError SendFrame(const uint8_t *aFrame, uint16_t aLength) override
    {
        uint8_t           header = 0;
        uint32_t          cmd    = 0;
        spinel_prop_key_t key    = SPINEL_PROP_LAST_STATUS;

        if (spinel_datatype_unpack(aFrame, aLength, "Cii", &header, &cmd, &key) > 0)
        {
            mLastHeader = header;
            mLastKey    = key;
        }
        return OT_ERROR_NONE;
    }

    otError WaitForFrame(uint64_t) override
    {
        uint8_t        frame[256];
        spinel_ssize_t packed = -1;

        if (!mSentResetStatus)
        {
            mSentResetStatus = true;
            packed = spinel_datatype_pack(frame, sizeof(frame), "Ciii", SPINEL_HEADER_FLAG, SPINEL_CMD_PROP_VALUE_IS,
                                          SPINEL_PROP_LAST_STATUS, SPINEL_STATUS_RESET_POWER_ON);
            PushRxFrame(frame, static_cast<uint16_t>(packed));
        }

        if (mLastKey == SPINEL_PROP_PROTOCOL_VERSION)
        {
            packed = spinel_datatype_pack(frame, sizeof(frame), "Ciiii", mLastHeader, SPINEL_CMD_PROP_VALUE_IS,
                                          SPINEL_PROP_PROTOCOL_VERSION, SPINEL_PROTOCOL_VERSION_THREAD_MAJOR,
                                          SPINEL_PROTOCOL_VERSION_THREAD_MINOR);
        }
        else if (mLastKey == SPINEL_PROP_NCP_VERSION)
        {
            packed = spinel_datatype_pack(frame, sizeof(frame), "CiiU", mLastHeader, SPINEL_CMD_PROP_VALUE_IS,
                                          SPINEL_PROP_NCP_VERSION, "OPENTHREAD/test");
        }
        else if (mLastKey == SPINEL_PROP_CAPS)
        {
            packed = spinel_datatype_pack(frame, sizeof(frame), "Ciii", mLastHeader, SPINEL_CMD_PROP_VALUE_IS,
                                          SPINEL_PROP_CAPS, SPINEL_CAP_CONFIG_FTD);
        }

        if (packed > 0)
        {
            PushRxFrame(frame, static_cast<uint16_t>(packed));
        }
        return OT_ERROR_NONE;
    }

    void PushRxFrame(const uint8_t *aFrame, uint16_t aLength)
    {
        for (uint16_t i = 0; i < aLength; ++i)
        {
            if (mFrameBuffer->WriteByte(aFrame[i]) != OT_ERROR_NONE)
            {
                mFrameBuffer->DiscardFrame();
                return;
            }
        }
        mCallback(mCallbackContext);
    }

    void                         UpdateFdSet(void *) override {}
    void                         Process(const void *) override {}
    uint32_t                     GetBusSpeed(void) const override { return 1000000; }
    otError                      HardwareReset(void) override { return OT_ERROR_NOT_IMPLEMENTED; }
    const otRcpInterfaceMetrics *GetRcpInterfaceMetrics(void) const override { return nullptr; }

    ReceiveFrameCallback mCallback        = nullptr;
    void                *mCallbackContext = nullptr;
    RxFrameBuffer       *mFrameBuffer     = nullptr;
    bool                 mSentResetStatus = false;
    uint8_t              mLastHeader      = 0;
    spinel_prop_key_t    mLastKey         = SPINEL_PROP_LAST_STATUS;
};

void Pump(otbr::MainloopContext &aMainloop)
{
    aMainloop.mMaxFd   = -1;
    aMainloop.mTimeout = {0, 0};
    FD_ZERO(&aMainloop.mReadFdSet);
    FD_ZERO(&aMainloop.mWriteFdSet);
    FD_ZERO(&aMainloop.mErrorFdSet);
    otbr::MainloopManager::GetInstance().Update(aMainloop);
    FD_ZERO(&aMainloop.mReadFdSet); // nothing is readable: no select() ran, frames come from the input
    FD_ZERO(&aMainloop.mErrorFdSet);
    otbr::MainloopManager::GetInstance().Process(aMainloop);
}

std::set<int> OpenFds(void)
{
    std::set<int> fds;
    DIR          *dir = opendir("/proc/self/fd");

    if (dir != nullptr)
    {
        int self = dirfd(dir);
        for (struct dirent *e = readdir(dir); e != nullptr; e = readdir(dir))
        {
            if (e->d_name[0] != '.' && atoi(e->d_name) != self)
            {
                fds.insert(atoi(e->d_name));
            }
        }
        closedir(dir);
    }
    return fds;
}

// True for an unsolicited (TID 0) PROP_VALUE_IS LAST_STATUS frame whose status is in the reset range.
// NcpSpinel::HandleNotification/HandleValueIs (src/host/ncp_spinel.cpp:363-369, :458-460) send such a frame to
// HandleNcpUnexpectedReset, which calls DieNow("NCP reset detected!") (:1194) by design: when the NCP resets,
// the border agent exits and its service manager restarts it. That is upstream's intentional restart path,
// not a bug, and since it exit()s the process a one-byte mutation of the last_status seed stalls the fuzzer.
// The check mirrors upstream's own decoding (kSpinelDataUnpackFormat "CiiD", then a packed uint status).
bool IsNcpResetNotification(const std::string &aFrame)
{
    const uint8_t    *frame  = reinterpret_cast<const uint8_t *>(aFrame.data());
    uint8_t           header = 0;
    unsigned int      cmd    = 0;
    spinel_prop_key_t key    = SPINEL_PROP_LAST_STATUS;
    const uint8_t    *data   = nullptr;
    spinel_size_t     len    = 0;
    unsigned int      status = SPINEL_STATUS_OK;

    if (spinel_datatype_unpack(frame, static_cast<spinel_size_t>(aFrame.size()), "CiiD", &header, &cmd, &key, &data,
                               &len) <= 0)
    {
        return false;
    }
    if (SPINEL_HEADER_GET_TID(header) != 0 || cmd != SPINEL_CMD_PROP_VALUE_IS || key != SPINEL_PROP_LAST_STATUS)
    {
        return false;
    }
    if (spinel_datatype_unpack(data, len, SPINEL_DATATYPE_UINT_PACKED_S, &status) <= 0)
    {
        return false;
    }
    return status >= SPINEL_STATUS_RESET__BEGIN && status <= SPINEL_STATUS_RESET__END;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FuzzInitLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    FuzzReader                in(aData, aSize);
    FakeNcpSpinelInterface    iface;
    ot::Spinel::SpinelDriver *driver    = static_cast<ot::Spinel::SpinelDriver *>(otSysGetSpinelDriver());
    spinel_iid_t              iidList[] = {0};
    otbr::MainloopContext     mainloop;
    std::set<int>             fdsBefore;

    {
        FuzzReader scan(aData, aSize);
        while (!scan.Empty())
        {
            std::string frame = scan.Chunk16();
            if (!frame.empty() && IsNcpResetNotification(frame))
            {
                return -1;
            }
        }
    }

    fdsBefore        = OpenFds(); // only descriptors this input opens are closed below, never the fuzzer's own
    sCoprocessorType = OT_COPROCESSOR_NCP;
    if (driver->Init(iface, /* aSoftwareReset */ false, iidList, 1) != OT_COPROCESSOR_NCP)
    {
        abort(); // the scripted handshake always yields an NCP
    }

    {
        otbr::Host::NcpHost host("wpan0", /* aBackboneInterfaceName */ "", /* aDryRun */ true);

        host.Init();
        Pump(mainloop);
        while (!in.Empty())
        {
            std::string frame = in.Chunk16();
            if (frame.empty())
            {
                continue;
            }
            iface.PushRxFrame(reinterpret_cast<const uint8_t *>(frame.data()), static_cast<uint16_t>(frame.size()));
            Pump(mainloop);
        }
        host.Deinit();
    }

    driver->Deinit();
    sCoprocessorType = OT_COPROCESSOR_UNKNOWN;

    for (int fd : OpenFds())
    {
        if (fdsBefore.count(fd) == 0)
        {
            close(fd);
        }
    }
    return 0;
}
