#pragma once
#include <windows.h>

typedef void (*post_call_hook_t)(void* return_addr);

int stackret_hook_install(void* target_func, post_call_hook_t hook_cb);
int stackret_hook_uninstall(void* target_func);
void stackret_hook_start_scanner(void);
void stackret_hook_stop_scanner(void);
