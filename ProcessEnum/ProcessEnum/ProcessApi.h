#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <vector>
#include <memory>
#include <string>
#include <print>    // C++23 std::print / std::println
#include <iostream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Wtsapi32.lib")