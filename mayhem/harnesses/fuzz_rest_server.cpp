// Fuzzes the REST server (rest::RestWebServer, src/rest/rest_web_server.cpp + cpp-httplib + the REST
// collections/actions behind it) through its real listening socket. The server is started once on a unix
// socket (the agent's `--rest-listen-address /path` mode) over OpenThread's fake platform, as upstream's
// REST gtests do; each input becomes one HTTP request sent over a fresh connection while the harness runs
// the agent main loop that the server's handlers post their work to.
//
// Input: [route][method][query chunk][header chunk][id chunk][body...], each chunk with a 2-byte little-endian
// length prefix (up to 65535 bytes, past cpp-httplib's request-line and header limits). Route and method pick from an
// allow-list of requests that cannot change the node's lasting state (no PUT /node/state, no dataset or
// commissioner writes, no factory reset, no device-collection delete), so every input starts from the same
// single-node leader. The query string and the `:id` path segment are percent-encoded so they stay within
// the chosen route; the extra header lines and the body are sent raw.
//
// State kept across inputs on purpose: the OpenThread instance and the server (created once). The only
// collections an allowed request can add to are the action queue and the diagnostics collection; both
// are emptied after every input with DELETE /api/actions and DELETE /api/diagnostics through the server,
// and the main loop then runs until the OpenThread commissioner an add-device or energy-scan action started
// is stopped again (CommissionerManager::Process stops it lazily). What still carries over is the leader's
// commissioner session ID and network data version, which each such input increments; no allowed request
// depends on their values.
#include "fuzz_common.hpp"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <openthread/commissioner.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>
#include <openthread/ip6.h>
#include <openthread/thread.h>

#include "common/mainloop.hpp"
#include "common/mainloop_manager.hpp"
#include "host/rcp_host.hpp"
#include "rest/rest_web_server.hpp"
#include "fake_platform.hpp"

using namespace otbr;

// Created once and never destroyed: static destructors would run after MainloopManager's.
static Host::RcpHost                       *sHost;
static std::shared_ptr<rest::RestWebServer> *sServer; // heap-held so no exit-time destructor runs
static MainloopContext                      sMainloop;
static std::string                          sSocketPath;

struct Route
{
    const char *mMethod;
    const char *mPath;
    bool        mWithId;
};

static const Route kRoutes[] = {
    {"GET", "/node", false},
    {"GET", "/node/ba-id", false},
    {"GET", "/node/state", false},
    {"GET", "/node/ext-address", false},
    {"GET", "/node/network-name", false},
    {"GET", "/node/rloc16", false},
    {"GET", "/node/leader-data", false},
    {"GET", "/node/num-of-router", false},
    {"GET", "/node/ext-panid", false},
    {"GET", "/node/rloc", false},
    {"GET", "/node/dataset/active", false},
    {"GET", "/node/dataset/pending", false},
    {"GET", "/node/commissioner/state", false},
    {"GET", "/node/commissioner/joiner", false},
    {"GET", "/node/coprocessor/version", false},
    {"GET", "/node/ba-epskc/state", false},
    {"GET", "/node/ba-epskc/key", false},
    {"GET", "/api/devices", false},
    {"GET", "/api/devices/", true},
    {"GET", "/api/node", false},
    {"GET", "/api/actions", false},
    {"GET", "/api/actions/", true},
    {"POST", "/api/actions", false},
    {"DELETE", "/api/actions", false},
    {"DELETE", "/api/actions/", true},
    {"GET", "/api/diagnostics", false},
    {"GET", "/api/diagnostics/", true},
    {"DELETE", "/api/diagnostics", false},
    {"DELETE", "/api/diagnostics/", true},
    {"GET", "/.well-known/thread/br-rest", false},
    {"OPTIONS", "/api/actions", false},
    {"GET", "/", true}, // unknown routes: the routing error handler
};

static void Pump(void)
{
    sMainloop.mMaxFd   = -1;
    sMainloop.mTimeout = {0, 0};
    FD_ZERO(&sMainloop.mReadFdSet);
    FD_ZERO(&sMainloop.mWriteFdSet);
    FD_ZERO(&sMainloop.mErrorFdSet);
    MainloopManager::GetInstance().Update(sMainloop);
    MainloopManager::GetInstance().Process(sMainloop);
}

static int Connect(void)
{
    struct sockaddr_un addr;
    int                fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0)
    {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sSocketPath.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

// Sends one request and runs the main loop until the server closes the connection.
static void Exchange(const std::string &aRequest)
{
    int    fd = -1;
    size_t sent = 0;
    char   buf[4096];

    for (int attempt = 0; attempt < 1000 && fd < 0; attempt++)
    {
        fd = Connect();
        if (fd < 0)
        {
            Pump();
            usleep(1000);
        }
    }
    if (fd < 0)
    {
        fprintf(stderr, "cannot connect to the REST server at %s\n", sSocketPath.c_str());
        abort();
    }

    while (sent < aRequest.size())
    {
        ssize_t n = send(fd, aRequest.data() + sent, aRequest.size() - sent, MSG_NOSIGNAL);
        if (n <= 0)
        {
            break;
        }
        sent += static_cast<size_t>(n);
    }
    shutdown(fd, SHUT_WR);

    for (;;)
    {
        struct pollfd pfd = {fd, POLLIN, 0};
        int           rc;

        Pump();
        rc = poll(&pfd, 1, 1);
        if (rc > 0)
        {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN))
            {
                break;
            }
        }
    }
    close(fd);
}

static std::string PercentEncode(const std::string &aIn)
{
    static const char kHex[] = "0123456789ABCDEF";
    std::string       out;

    for (unsigned char c : aIn)
    {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '=' || c == '&' || c == ',')
        {
            out.push_back(static_cast<char>(c));
        }
        else
        {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0xf]);
        }
    }
    return out;
}

static std::string MakeRequest(const char        *aMethod,
                               const std::string &aTarget,
                               const std::string &aHeaders,
                               const std::string &aBody)
{
    std::string req = std::string(aMethod) + " " + aTarget + " HTTP/1.1\r\nHost: localhost\r\n";

    req += aHeaders;
    req += "Content-Length: " + std::to_string(aBody.size()) + "\r\n\r\n";
    req += aBody;
    return req;
}

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    const char *tmp = getenv("TMPDIR");
    std::string dirTemplate = std::string((tmp != nullptr && tmp[0] != '\0') ? tmp : "/tmp") + "/otbr-rest-XXXXXX";
    std::vector<char> dir(dirTemplate.begin(), dirTemplate.end());

    FuzzInitLogging();

    dir.push_back('\0');
    if (mkdtemp(dir.data()) == nullptr)
    {
        perror("mkdtemp");
        abort();
    }
    sSocketPath = std::string(dir.data()) + "/rest.sock";

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
        Pump();
    }

    sServer = new std::shared_ptr<rest::RestWebServer>(std::make_shared<rest::RestWebServer>(*sHost));
    (*sServer)->Init(sSocketPath, 0);
    Exchange(MakeRequest("GET", "/node/state", "", "")); // waits until the server listens
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    FuzzReader   in(aData, aSize);
    const Route &route   = kRoutes[in.Byte() % (sizeof(kRoutes) / sizeof(kRoutes[0]))];
    uint8_t      flags   = in.Byte();
    std::string  query   = in.Chunk16();
    std::string  headers = in.Chunk16();
    std::string  id      = in.Chunk16();
    std::string  body    = in.Rest();
    std::string  target  = route.mPath;
    std::string  hdrs;

    if (route.mWithId)
    {
        target += PercentEncode(id);
    }
    if (!query.empty())
    {
        target += "?" + PercentEncode(query);
    }
    hdrs += (flags & 1) ? "Accept: application/json\r\n" : "Accept: application/vnd.api+json\r\n";
    if (flags & 2)
    {
        hdrs += (flags & 4) ? "Content-Type: application/json\r\n" : "Content-Type: application/vnd.api+json\r\n";
    }
    if (!headers.empty())
    {
        hdrs += headers;
        if (headers.back() != '\n')
        {
            hdrs += "\r\n";
        }
    }

    Exchange(MakeRequest(route.mMethod, target, hdrs, body));

    // Reset the two collections an allowed request can add to.
    Exchange(MakeRequest("DELETE", "/api/actions", "Accept: application/vnd.api+json\r\n", ""));
    Exchange(MakeRequest("DELETE", "/api/diagnostics", "Accept: application/vnd.api+json\r\n", ""));
    for (int i = 0; i < 1000 && otCommissionerGetState(ot::FakePlatform::CurrentInstance()) !=
                                    OT_COMMISSIONER_STATE_DISABLED;
         i++)
    {
        Pump();
    }
    return 0;
}
