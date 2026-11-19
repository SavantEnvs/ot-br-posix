// Shared helpers for the ot-br-posix fuzz harnesses (mayhem layer, not upstream code).
#ifndef OTBR_MAYHEM_FUZZ_COMMON_HPP_
#define OTBR_MAYHEM_FUZZ_COMMON_HPP_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "common/logging.hpp"

// Quiet, syslog-free logging: logging is process-global and set once, never changed by an input.
static inline void FuzzInitLogging(void)
{
    otbrLogInit("otbr-fuzz", OTBR_LOG_CRIT, /* aPrintStderr */ false, /* aSyslogDisable */ true);
}

// Consumes length-prefixed chunks (2-byte little-endian length, so a chunk can be up to 65535 bytes) from
// the input; a length past the end takes the rest.
class FuzzReader
{
public:
    FuzzReader(const uint8_t *aData, size_t aSize)
        : mData(aData)
        , mSize(aSize)
    {
    }

    bool Empty(void) const { return mSize == 0; }

    uint8_t Byte(void)
    {
        uint8_t b = 0;
        if (mSize > 0)
        {
            b = mData[0];
            mData++;
            mSize--;
        }
        return b;
    }

    std::string Chunk16(void)
    {
        size_t len = Byte();
        len |= static_cast<size_t>(Byte()) << 8;
        if (len > mSize)
        {
            len = mSize;
        }
        std::string s(reinterpret_cast<const char *>(mData), len);
        mData += len;
        mSize -= len;
        return s;
    }

    std::string Rest(void)
    {
        std::string s(reinterpret_cast<const char *>(mData), mSize);
        mData += mSize;
        mSize = 0;
        return s;
    }

private:
    const uint8_t *mData;
    size_t         mSize;
};

#endif
