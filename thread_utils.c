#include "thread_utils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>

int enum_threads(thread_info_t** out_threads, size_t* out_count) {
    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return -1;

    thread_info_t* list = NULL;
    size_t capacity = 64;
    size_t count = 0;
    list = malloc(sizeof(thread_info_t) * capacity);
    if (!list) {
        CloseHandle(snapshot);
        return -1;
    }

    if (Thread32First(snapshot, &te32)) {
        do {
            if (count >= capacity) {
                capacity *= 2;
                void* tmp = realloc(list, capacity * sizeof(thread_info_t));
                if (!tmp) {
                    free(list);
                    CloseHandle(snapshot);
                    return -1;
                }
                list = tmp;
            }
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread) {
                list[count].thread_handle = hThread;
                list[count].thread_id = te32.th32ThreadID;
                count++;
            }
        } while (Thread32Next(snapshot, &te32));
    }
    CloseHandle(snapshot);
    *out_threads = list;
    *out_count = count;
    return 0;
}

void free_thread_list(thread_info_t* threads, size_t count) {
    for (size_t i = 0; i < count; i++) {
        CloseHandle(threads[i].thread_handle);
    }
    free(threads);
}

int suspend_thread_and_get_context(HANDLE thread, CONTEXT* ctx) {
    if (SuspendThread(thread) == (DWORD)-1) return -1;
    ctx->ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(thread, ctx)) {
        ResumeThread(thread);
        return -1;
    }
    return 0;
}

int resume_thread(HANDLE thread) {
    if (ResumeThread(thread) == (DWORD)-1) return -1;
    return 0;
}

int read_thread_stack(HANDLE thread, CONTEXT* ctx, void** out_stack_base, size_t* out_stack_size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)ctx->Rsp, &mbi, sizeof(mbi))) return -1;
    if (!out_stack_base || !out_stack_size) return -1;
    *out_stack_base = (void*)mbi.BaseAddress;
    *out_stack_size = (size_t)((uintptr_t)ctx->Rsp - (uintptr_t)mbi.BaseAddress);
    return 0;
}
