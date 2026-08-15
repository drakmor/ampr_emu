/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR reactor arena allocator.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

void* ampr_reactor_arena_alloc(size_t size, size_t alignment);
void ampr_reactor_arena_free(void* ptr, size_t size);

template <typename T>
struct AmprReactorAllocator {
    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    AmprReactorAllocator() noexcept = default;
    template <typename U>
    AmprReactorAllocator(const AmprReactorAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (n > SIZE_MAX / sizeof(T)) {
            __builtin_trap();
        }
        const size_t bytes = n == 0 ? sizeof(T) : n * sizeof(T);
        return static_cast<T*>(ampr_reactor_arena_alloc(bytes, alignof(T)));
    }

    void deallocate(T* ptr, std::size_t n) noexcept {
        ampr_reactor_arena_free(ptr, n * sizeof(T));
    }

    template <typename U>
    struct rebind {
        using other = AmprReactorAllocator<U>;
    };
};

template <typename T, typename U>
inline bool operator==(const AmprReactorAllocator<T>&, const AmprReactorAllocator<U>&) noexcept {
    return true;
}

template <typename T, typename U>
inline bool operator!=(const AmprReactorAllocator<T>&, const AmprReactorAllocator<U>&) noexcept {
    return false;
}
