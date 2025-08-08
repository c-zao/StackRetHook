#include "utils.h"
#include <stdio.h>
#include <stdarg.h>

void* alloc_executable(size_t size) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void free_executable(void* ptr, size_t size) {
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

void log_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
