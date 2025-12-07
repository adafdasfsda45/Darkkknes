#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>

const std::string TARGET_STRING = "EnablePrimaryMouseButtonEvents(true)";

std::string FileTimeToString(const FILETIME& ft) {
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    char buffer[256];
    sprintf_s(buffer, "%02d.%02d.%04d %02d:%02d:%02d",
        stLocal.wDay, stLocal.wMonth, stLocal.wYear,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    return std::string(buffer);
}

void CheckPrefetch() {
    std::cout << "\n[!] Checking Prefetch for history..." << std::endl;

    std::wstring prefetchPath = L"C:\\Windows\\Prefetch\\LGHUB_AGENT.EXE*.pf";

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(prefetchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cout << "Prefetch traces not found. (Never run or cleared)" << std::endl;
    }
    else {
        FILETIME lastRunTime = { 0, 0 };
        bool foundAny = false;

        do {
            if (CompareFileTime(&findData.ftLastWriteTime, &lastRunTime) > 0) {
                lastRunTime = findData.ftLastWriteTime;
                foundAny = true;
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);

        if (foundAny) {
            std::cout << "Found Prefetch entry!" << std::endl;
            std::cout << "Last launch time: " << FileTimeToString(lastRunTime) << std::endl;
        }
    }
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processId;
}

int main() {
    SetConsoleTitleW(L"LGHUB Scanner + History Check");

    std::cout << "Scanning..." << std::endl;

    DWORD pid = GetProcessIdByName(L"lghub_agent.exe");

    if (pid == 0) {
        std::cout << "LGHUB Agent not found (process not running)." << std::endl;
        CheckPrefetch();
        std::cout << "\nResult: Process is dead." << std::endl;
        system("pause");
        return 0;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open process. Run as Administrator." << std::endl;
        system("pause");
        return 0;
    }

    unsigned char* addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    bool found = false;
    char* buffer = nullptr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            if (mbi.RegionSize > 0) {
                buffer = new char[mbi.RegionSize];
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                    char* bufStart = buffer;
                    char* bufEnd = buffer + bytesRead;
                    const char* targetStart = TARGET_STRING.c_str();
                    const char* targetEnd = targetStart + TARGET_STRING.length();

                    auto it = std::search(bufStart, bufEnd, targetStart, targetEnd);

                    if (it != bufEnd) {
                        found = true;
                        delete[] buffer;
                        break;
                    }
                }
                delete[] buffer;
            }
        }
        addr += mbi.RegionSize;
    }

    CloseHandle(hProcess);

    if (found) {
        std::cout << "Yes (ne nado igat s macrosom)" << std::endl;
    }
    else {
        std::cout << "No" << std::endl;
    }

    system("pause");
    return 0;
}
