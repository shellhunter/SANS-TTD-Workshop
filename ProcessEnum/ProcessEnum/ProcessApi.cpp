#include "ProcessApi.h"

void EnumerateProcesses_PSAPI() {
    std::vector<DWORD> pids(1024);
    DWORD bytesReturned{};

    if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &bytesReturned)) {
        std::print("[!] EnumProcesses failed.\n");
        return;
    }

    pids.resize(bytesReturned / sizeof(DWORD));

    for (DWORD pid : pids) {
        if (pid == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) continue;

        std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)> processHandle(hProcess, CloseHandle);

        WCHAR processName[MAX_PATH] = L"<unknown>";
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(processHandle.get(), &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameW(processHandle.get(), hMod, processName, std::size(processName));
        }

        std::wcout << std::format(L"\t >> PID: {:5} | Name: {}\n", pid, std::wstring_view(processName));
    }
}


void EnumerateProcesses_Toolhelp() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::print("[!] Failed to create snapshot.\n");
        return;
    }

    std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)> handle(snapshot, CloseHandle);

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(handle.get(), &entry)) {
        std::print("[!] Process32First failed.\n");
        return;
    }

    do {
        std::wcout << std::format(L"\t >> PID: {:5} | Name: {}\n", entry.th32ProcessID, std::wstring_view(entry.szExeFile));
    } while (Process32NextW(handle.get(), &entry));
}

void EnumerateProcesses_WTS() {
    PWTS_PROCESS_INFOW pInfo = nullptr;
    DWORD count = 0;

    if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pInfo, &count)) {
        std::print("[!] WTSEnumerateProcesses failed.\n");
        return;
    }

    std::unique_ptr<std::remove_pointer_t<PWTS_PROCESS_INFOW>, decltype(&WTSFreeMemory)>
        processInfo(pInfo, WTSFreeMemory);

    for (DWORD i = 0; i < count; ++i) {
        const auto& proc = processInfo.get()[i];
        std::wstring name = proc.pProcessName ? proc.pProcessName : L"<null>";
        std:: wcout << std::format(L"\t >> PID: {:5} | Name: {}\n", proc.ProcessId, name);
    }
}

int main() {
    std::print("\nToolhelp Snapshot:\n");
    EnumerateProcesses_Toolhelp();

    std::print("\nPSAPI EnumProcesses:\n");
    EnumerateProcesses_PSAPI();

    std::print("\nWTS Enumerate:\n");
    EnumerateProcesses_WTS();

    return 0;
}
