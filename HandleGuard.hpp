#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

class HandleGuard {
public:
    using OSHandle = HANDLE;

    explicit HandleGuard(OSHandle handle) noexcept
        : handle_(handle) {
    }

    ~HandleGuard() noexcept {
        Close();
    }

    HandleGuard(HandleGuard&& other) noexcept
        : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    OSHandle get() const noexcept {
        return handle_;
    }

    void Close() noexcept {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    OSHandle handle_ = INVALID_HANDLE_VALUE;
};
