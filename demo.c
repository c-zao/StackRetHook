#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "stackret_hook.h"

static void post_call_hook(void* ret_addr) {
    printf("function returned, original return address: %p\n", ret_addr);
}

#ifdef _DLL_BUILD

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        if (AllocConsole()) {
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
            freopen("CONIN$", "r", stdin);
        }

        if (stackret_hook_install((void*)MessageBoxW, post_call_hook) != 0) {
            printf("failed to install hook\n");
        }
        else {
            stackret_hook_start_scanner();
        }

        MessageBoxW(NULL, L"dll", L"stackrethook demo", MB_OK);
        break;

    case DLL_PROCESS_DETACH:
        stackret_hook_stop_scanner();
        stackret_hook_uninstall((void*)MessageBoxW);
        break;
    }
    return TRUE;
}

#else  // exe build

int main(void) {

    if (stackret_hook_install((void*)MessageBoxW, post_call_hook) != 0) {
        fprintf(stderr, "failed to install hook\n");
        return 1;
    }

    stackret_hook_start_scanner();

    MessageBoxW(NULL, L"exe!", L"stackrethook demo", MB_OK);

    getchar();

    stackret_hook_stop_scanner();
    stackret_hook_uninstall((void*)MessageBoxW);

    return 0;
}

#endif
