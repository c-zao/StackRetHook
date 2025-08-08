#pragma once
#include <windows.h>

typedef struct {
    HANDLE thread_handle;
    DWORD thread_id;
} thread_info_t;

int enum_threads(thread_info_t** out_threads, size_t* out_count);
void free_thread_list(thread_info_t* threads, size_t count);
int suspend_thread_and_get_context(HANDLE thread, CONTEXT* ctx);
int resume_thread(HANDLE thread);
int read_thread_stack(HANDLE thread, CONTEXT* ctx, void** out_stack_base, size_t* out_stack_size);
