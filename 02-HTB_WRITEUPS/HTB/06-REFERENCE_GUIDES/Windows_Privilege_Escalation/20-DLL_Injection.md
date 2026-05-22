# Section 20 — DLL Injection

> **Lab: no** — concepts only. Covers DLL injection methods and DLL hijacking techniques.

**Core principle:** DLL injection inserts code into a running process by loading a malicious DLL into its address space. DLL hijacking exploits the Windows DLL search order to make an application load a malicious DLL instead of (or in addition to) the legitimate one. Both techniques let an attacker execute code in the context of the target process — if that process runs as SYSTEM, you get SYSTEM.

---

## DLL injection methods

| Method | Complexity | Stealth | Detection |
|--------|-----------|---------|-----------|
| **LoadLibrary** | Low | Low | Easily detected — LoadLibrary calls are monitored |
| **Manual Mapping** | Very high | High | Avoids LoadLibrary — harder to detect |
| **Reflective DLL Injection** | High | High | DLL loads itself from memory — no file on disk |

---

## Method 1: LoadLibrary injection

The classic approach — uses `CreateRemoteThread` to call `LoadLibrary` in the target process.

```
1. OpenProcess() → get handle to target process (needs PROCESS_ALL_ACCESS)
2. VirtualAllocEx() → allocate memory in target process for DLL path string
3. WriteProcessMemory() → write the DLL path into allocated memory
4. GetProcAddress(kernel32, "LoadLibraryA") → get address of LoadLibrary
5. CreateRemoteThread() → create thread in target process starting at LoadLibrary
   → thread argument = pointer to DLL path in remote memory
6. Target process loads your DLL → DllMain executes in target's context
```

> Easy to implement but easily detected. Security tools monitor `CreateRemoteThread` and `LoadLibrary` calls.

---

## Method 2: Manual Mapping

Avoids `LoadLibrary` entirely — manually performs everything the Windows loader would do.

```
1. Read DLL as raw bytes into injector process
2. Allocate memory in target process
3. Map DLL sections (headers, .text, .data, etc.) into target memory
4. Inject shellcode that:
   a. Processes relocation table (fixes addresses)
   b. Resolves imports (loads dependencies, resolves function addresses)
   c. Executes TLS callbacks
   d. Calls DllMain(DLL_PROCESS_ATTACH)
```

> Very complex to implement. Avoids `LoadLibrary` monitoring but requires deep understanding of the PE format.

---

## Method 3: Reflective DLL Injection

The DLL contains its own loader (ReflectiveLoader function) and loads itself from memory.

```
1. Write DLL into target process memory (any location)
2. Transfer execution to ReflectiveLoader (exported function in the DLL)
3. ReflectiveLoader:
   a. Finds its own image location in memory
   b. Parses kernel32.dll exports to find LoadLibraryA, GetProcAddress, VirtualAlloc
   c. Allocates proper memory region
   d. Maps its own headers and sections
   e. Resolves its own imports
   f. Processes relocations
   g. Calls DllMain(DLL_PROCESS_ATTACH)
```

> Used by Meterpreter and many C2 frameworks. No DLL file on disk — entirely in memory. Reference: Stephen Fewer's ReflectiveDLLInjection on GitHub.

---

## DLL Hijacking

Instead of injecting into a running process, exploit the DLL search order to make an application load your DLL on startup.

### DLL search order (Safe DLL Search Mode enabled — default)

```
1. Application directory (where the .exe lives)
2. C:\Windows\System32
3. C:\Windows\System (16-bit, legacy)
4. C:\Windows
5. Current working directory
6. Directories in PATH environment variable
```

### DLL search order (Safe DLL Search Mode disabled)

```
1. Application directory
2. Current working directory  ← moved up!
3. C:\Windows\System32
4. C:\Windows\System
5. C:\Windows
6. PATH directories
```

> Registry key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode` (1 = enabled, 0 = disabled)

### Finding hijackable DLLs

**Tool 1: Process Monitor (procmon)**
- Filter: Process Name = `<target.exe>`, Operation = `CreateFile`, Result = `NAME NOT FOUND`, Path ends with `.dll`
- Shows every DLL the application tried to load but couldn't find — prime hijack targets

**Tool 2: Process Explorer**
- Select process → Properties → view loaded DLLs
- Shows what's currently loaded — useful for proxying attacks

**Tool 3: PE Explorer**
- Open the .exe → view import table → see which DLLs it expects

---

## DLL Hijacking technique 1: Proxying

Replace a DLL the application successfully loads, but proxy calls through to the original so the application still works.

```
1. Rename original library.dll → library.o.dll
2. Create malicious library.dll that:
   a. Loads library.o.dll
   b. Calls original functions from library.o.dll
   c. Tampers with results or executes additional malicious code
   d. Returns results to the calling application
3. Application loads your library.dll thinking it's the real one
```

> Application continues to function (original functions still available via proxy). Your code executes in addition to the legitimate functionality. Stealthier than outright replacement.

---

## DLL Hijacking technique 2: Missing DLL (phantom DLL)

Place a malicious DLL where the application searches for one that doesn't exist.

```
1. Use procmon to find DLLs with "NAME NOT FOUND" in the app's directory
2. Create a malicious DLL with that filename
3. Place it in the search path (app directory, PATH directory, etc.)
4. Application loads your DLL on next startup
5. DllMain executes your code (DLL_PROCESS_ATTACH)
```

> Simplest form of hijacking. No need to proxy original functions — the DLL didn't exist in the first place. The UAC bypass in Section 16 (srrstr.dll + SystemPropertiesAdvanced.exe) is exactly this technique.

---

## DLL Hijacking technique 3: Search order hijacking

Place a DLL earlier in the search order than the legitimate copy.

```
1. Application loads legit.dll from C:\Windows\System32
2. Place malicious legit.dll in the application directory (searched first)
3. Application loads your copy instead of the System32 version
```

> Only works if you have write access to a directory searched before the legitimate DLL's location.

---

## Relevance to privilege escalation

| Scenario | Result |
|----------|--------|
| Hijack DLL for a SYSTEM service | Code execution as SYSTEM |
| Hijack DLL for an auto-elevating binary | UAC bypass (Section 16) |
| Hijack DLL for a high-privilege user's startup app | Code execution as that user |
| Inject into a SYSTEM process | Code execution as SYSTEM |

---

## Key takeaways

- **DLL injection = code into running process. DLL hijacking = code loaded on process start.** Different approaches, same goal.
- **LoadLibrary injection is the simplest** but most detectable. Reflective injection (used by Meterpreter) is stealthiest.
- **procmon is the primary tool for finding hijackable DLLs.** Filter for NAME NOT FOUND on .dll paths.
- **Missing DLLs in user-writable PATH locations are free wins.** The srrstr.dll/SystemPropertiesAdvanced.exe UAC bypass is a textbook example.
- **Proxying keeps the application functional** while injecting malicious code — important for stealth and avoiding crashes.
- **Safe DLL Search Mode (default on)** pushes current directory lower in search order, reducing attack surface.
- **On the CPTS exam:** DLL hijacking is more likely than injection. Look for services/apps loading DLLs from writable paths, or auto-elevating binaries with missing DLLs.
