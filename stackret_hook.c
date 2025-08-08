#define _CRT_SECURE_NO_WARNINGS
#include "stackret_hook.h"
#include "thread_utils.h"
#include "utils.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>

typedef struct hook_entry_s {
    void* target_func;
    void* trampoline;
    post_call_hook_t callback;
    void* original_return;
    struct hook_entry_s* next;
} hook_entry_t;

static hook_entry_t* g_hooks = NULL;
static SRWLOCK g_hooks_lock = SRWLOCK_INIT;

static volatile LONG g_scanner_running = 0;
static HANDLE g_scanner_thread = NULL;

static void build_trampoline(hook_entry_t* hook) {
    unsigned char code[] = {
        0x48, 0x8B, 0x04, 0x24,             // mov rax,[rsp]
        0x48, 0xA3, 0,0,0,0,0,0,0,0,       // mov [hook->original_return], rax
        0x48, 0x89, 0xC1,                   // mov rcx, rax
        0x48, 0xB8, 0,0,0,0,0,0,0,0,       // mov rax, hook->callback
        0xFF, 0xD0,                         // call rax
        0x48, 0x8B, 0x04, 0x24,             // mov rax,[rsp]
        0x48, 0xA3, 0,0,0,0,0,0,0,0,       // mov [hook->original_return], rax
        0x48, 0x8B, 0x3C, 0x24,             // mov rdi,[rsp]
        0x48, 0x89, 0x3C, 0x24,             // mov [rsp], rdi
        0xC3                                // ret
    };

    unsigned char* p = alloc_executable(sizeof(code));
    if (!p) return;

    memcpy(p, code, sizeof(code));

    *(void**)(p + 5) = &hook->original_return;
    *(void**)(p + 14) = (void*)hook->callback;
    *(void**)(p + 22) = &hook->original_return;

    hook->trampoline = p;
}

static void patch_return_address(void* ret_addr, void* new_addr) {
    DWORD oldProtect;
    SIZE_T bytesWritten;
    VirtualProtect(ret_addr, sizeof(void*), PAGE_READWRITE, &oldProtect);
    memcpy(ret_addr, &new_addr, sizeof(void*));
    VirtualProtect(ret_addr, sizeof(void*), oldProtect, &oldProtect);
}

static void scan_thread_stack_for_hooks(thread_info_t* thread, hook_entry_t* hooks) {
    CONTEXT ctx = { 0 };
    if (suspend_thread_and_get_context(thread->thread_handle, &ctx) != 0)
        return;

    void* stack_base = NULL;
    size_t stack_size = 0;
    if (read_thread_stack(thread->thread_handle, &ctx, &stack_base, &stack_size) != 0) {
        resume_thread(thread->thread_handle);
        return;
    }

    uintptr_t addr_start = (uintptr_t)stack_base;
    uintptr_t addr_end = addr_start + stack_size;

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    for (uintptr_t addr = addr_start; addr < addr_end; addr += mbi.RegionSize) {
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {

            addr += 0x1000; 
            continue;
        }

        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            continue;
        }

        uintptr_t page_start = (uintptr_t)mbi.BaseAddress;
        uintptr_t page_end = page_start + mbi.RegionSize;
        if (page_end > addr_end) page_end = addr_end;

        void** p = (void**)page_start;
        void** p_end = (void**)page_end;

        for (; p < p_end; p++) {

            hook_entry_t* cur = hooks;
            while (cur) {
                if (*p == cur->target_func) {
                    patch_return_address(p, cur->trampoline);
                }
                cur = cur->next;
            }
        }
    }

    resume_thread(thread->thread_handle);
}

static DWORD WINAPI scanner_thread_proc(LPVOID param) {
    (void)param;
    while (InterlockedCompareExchange(&g_scanner_running, 1, 1)) {
        thread_info_t* threads = NULL;
        size_t count = 0;
        if (enum_threads(&threads, &count) == 0) {
            AcquireSRWLockShared(&g_hooks_lock);
            scan_thread_stack_for_hooks(threads, g_hooks);
            ReleaseSRWLockShared(&g_hooks_lock);
            free_thread_list(threads, count);
        }
        Sleep(50);
    }
    return 0;
}

int stackret_hook_install(void* target_func, post_call_hook_t hook_cb) {
    if (!target_func || !hook_cb) return -1;
    AcquireSRWLockExclusive(&g_hooks_lock);
    hook_entry_t* cur = g_hooks;
    while (cur) {
        if (cur->target_func == target_func) {
            ReleaseSRWLockExclusive(&g_hooks_lock);
            return -1;
        }
        cur = cur->next;
    }

    hook_entry_t* h = malloc(sizeof(hook_entry_t));
    if (!h) {
        ReleaseSRWLockExclusive(&g_hooks_lock);
        return -1;
    }
    h->target_func = target_func;
    h->callback = hook_cb;
    h->original_return = NULL;
    h->trampoline = NULL;
    h->next = g_hooks;
    g_hooks = h;

    build_trampoline(h);
    ReleaseSRWLockExclusive(&g_hooks_lock);
    return 0;
}

int stackret_hook_uninstall(void* target_func) {
    AcquireSRWLockExclusive(&g_hooks_lock);
    hook_entry_t** cur = &g_hooks;
    while (*cur) {
        if ((*cur)->target_func == target_func) {
            hook_entry_t* to_remove = *cur;
            *cur = to_remove->next;
            free_executable(to_remove->trampoline, 64);
            free(to_remove);
            ReleaseSRWLockExclusive(&g_hooks_lock);
            return 0;
        }
        cur = &(*cur)->next;
    }
    ReleaseSRWLockExclusive(&g_hooks_lock);
    return -1;
}

void stackret_hook_start_scanner(void) {
    if (InterlockedCompareExchange(&g_scanner_running, 1, 0) == 0) {
        g_scanner_thread = CreateThread(NULL, 0, scanner_thread_proc, NULL, 0, NULL);
    }
}

void stackret_hook_stop_scanner(void) {
    if (InterlockedCompareExchange(&g_scanner_running, 0, 1) == 1) {
        WaitForSingleObject(g_scanner_thread, INFINITE);
        CloseHandle(g_scanner_thread);
        g_scanner_thread = NULL;
    }
}
