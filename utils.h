#pragma once
#include <windows.h>

void* alloc_executable(size_t size);
void free_executable(void* ptr, size_t size);
void log_printf(const char* fmt, ...);
