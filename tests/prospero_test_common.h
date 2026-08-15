#pragma once

#include <ampr.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

inline bool expect_rc(const char* label, int got, int expected) {
    if (got == expected) {
        return true;
    }
    std::printf("FAIL %s got=0x%x expected=0x%x\n", label, got, expected);
    return false;
}

inline bool expect_true(const char* label, bool value) {
    if (value) {
        return true;
    }
    std::printf("FAIL %s\n", label);
    return false;
}

struct ScopedAlignedBuffer {
    void* ptr{nullptr};
    size_t size{0};

    explicit ScopedAlignedBuffer(size_t sizeIn) : size(sizeIn) {
        ptr = ::aligned_alloc(64, sizeIn);
        if (ptr) {
            std::memset(ptr, 0, sizeIn);
        }
    }

    ~ScopedAlignedBuffer() {
        std::free(ptr);
    }

    ScopedAlignedBuffer(const ScopedAlignedBuffer&) = delete;
    ScopedAlignedBuffer& operator=(const ScopedAlignedBuffer&) = delete;
};
