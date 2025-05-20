### PowerShell Shellcode Injection via APC Queuing

### Overview

Asynchronous Procedure Call (APC) queuing to execute shellcode within the context of a thread. It uses key Windows APIs `VirtualAlloc`, `QueueUserAPC`, `OpenThread`, and `GetCurrentThreadId` to allocate memory, inject shellcode, and execute it by queuing an APC.

### Usage

```
powershell -File sc_loader.ps1 -b64EncSc "<Base64EncodedXORedShellcode>" -scXorKey <Byte>
```

* **`-b64EncSc`**: The Base64 encoded XORed shellcode to be injected.
* **`-scXorKey`**: XOR key to decrypt the shellcode.

### Execution Flow:

1. **Decryption of Shellcode:**

   * The provided shellcode is Base64 decoded and XOR decrypted using the specified key.

2. **Dynamic Function Importing:**

   * The script dynamically imports critical Windows APIs (`VirtualAlloc`, `QueueUserAPC`, etc.) using .NET reflection and DllImport.

3. **Memory Allocation:**

   * Allocates memory with `VirtualAlloc` to hold the decrypted shellcode with execution permissions (`0x40`).

4. **APC Queuing:**

   * The current thread is opened with `OpenThread` using `0x1F03FF` permissions, granting full control.
   * The shellcode address is queued as an APC to the thread using `QueueUserAPC`.

5. **Triggering APC:**

   * The thread is put into an alertable state using `SleepEx` to execute the APC and run the shellcode.

### Notes:

* **Execution of Shellcode:** The script demonstrates how to execute arbitrary code within a legitimate thread, a common technique in malware post-exploitation.
* **APC Queuing:** APC injection is a stealthy method of running code in the context of another thread, bypassing common detection mechanisms.
* **Dynamic Imports:** Dynamically resolving API functions at runtime complicates static analysis and signature-based detection.

* Usage of `OpenThread` with `0x1F03FF` permissions provides full access, potentially enabling malicious control over any thread.
* The use of APCs can evade user-mode hooks, making it effective in bypassing endpoint security solutions.
* Memory permissions set with `0x40` allow both read and execute, a typical indicator for malicious shellcode injection.
