# StackRetHook

A minimal C framework for Windows that hooks functions by patching their return addresses on thread stacks. It allows executing custom code right after the hooked function returns.

---

## Features

- Hook functions by specifying their target address.
- Execute a user-defined callback immediately after the original function returns.
- Support multiple hooks simultaneously.
- Safely scans all threads’ stacks by suspending them temporarily.
- Avoids access violations by carefully validating memory during stack scanning.
- Simple and lightweight with minimal dependencies.

---

## How it works

1. **Hook Installation:**  
   Register a hook by providing the target function address and a callback function.

2. **Trampoline Allocation:**  
   The framework creates a trampoline that calls your callback when the hooked function returns.

3. **Stack Scanning:**  
   A background thread periodically suspends other threads and scans their stacks for return addresses matching any hooked function.

4. **Return Address Patching:**  
   When it finds a return address pointing to a hooked function, it replaces it with the trampoline address.

5. **Callback Execution:**  
   After the hooked function finishes, the trampoline runs your callback, passing it the original return address, then resumes normal execution.
