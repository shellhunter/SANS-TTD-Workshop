#include <windows.h>
#include <print>        // C++23 std::println
#include <system_error> // for std::system_error
#include <string_view>
#include <iostream>

void GatherOSInfo()
{
    SYSTEM_INFO sysinfo{};
    GetNativeSystemInfo(&sysinfo);

    std::println("Processors: {}", sysinfo.dwNumberOfProcessors);
    std::println("Page size: {} bytes", sysinfo.dwPageSize);
    std::println("Processor type: {}", sysinfo.dwProcessorType);
    std::println("Min application address: {:#x}", reinterpret_cast<std::uint64_t>(sysinfo.lpMinimumApplicationAddress));
    std::println("Max application address: {:#x}", reinterpret_cast<std::uint64_t>(sysinfo.lpMaximumApplicationAddress));

    // --- OS version via RtlGetVersion ---
    using RtlGetVersionFn = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    auto rtlGetVersion = ntdll
        ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"))
        : nullptr;

    if (!rtlGetVersion) {
        std::println("Could not locate RtlGetVersion in ntdll.dll");
        return;
    }

    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    NTSTATUS status = rtlGetVersion(&vi);

    if (status != 0 /* STATUS_SUCCESS */) {
        std::println("RtlGetVersion failed with NTSTATUS 0x{:X}", static_cast<unsigned>(status));
        return;
    }

    std::cout << std::format(
        "OS Version: {}.{}.{}\n",
        vi.dwMajorVersion,
        vi.dwMinorVersion,
        vi.dwBuildNumber
    );
}

int main()
{
    std::println("This program will gather basic information about the OS");
    GatherOSInfo();
    return EXIT_SUCCESS;
}