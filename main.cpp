#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <set>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "version")
#pragma comment(lib, "shlwapi")

const std::string LGHUB_MACRO_STRING = "EnablePrimaryMouseButtonEvents(true)";
std::set<std::wstring> g_ReportedFiles;

unsigned __int64 FileTimeToQuadWord(FILETIME* ft) {
    return (static_cast<unsigned __int64>(ft->dwHighDateTime) << 32) + ft->dwLowDateTime;
}

unsigned __int64 GetCurrentTimeQuad() {
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    return FileTimeToQuadWord(&ftNow);
}

bool IsWithinLast10Minutes(FILETIME ftCheck) {
    unsigned __int64 tCheck = FileTimeToQuadWord(&ftCheck);
    unsigned __int64 tNow = GetCurrentTimeQuad();
    unsigned __int64 tenMinutesTicks = 6000000000ULL;
    if (tCheck > tNow) return false;
    return (tNow - tCheck) <= tenMinutesTicks;
}

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

std::set<std::wstring> GetRunningProcesses() {
    std::set<std::wstring> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                std::wstring name = pe.szExeFile;
                std::transform(name.begin(), name.end(), name.begin(), ::towupper);
                processes.insert(name);
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return processes;
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

std::wstring ResolvePath(const std::wstring& exeName) {
    wchar_t buffer[MAX_PATH];
    if (SearchPathW(NULL, exeName.c_str(), L".exe", MAX_PATH, buffer, NULL)) {
        return std::wstring(buffer);
    }
    std::wstring psPath = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\" + exeName;
    if (GetFileAttributesW(psPath.c_str()) != INVALID_FILE_ATTRIBUTES) return psPath;

    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring frameworkPath = std::wstring(winDir) + L"\\Microsoft.NET\\Framework64\\v4.0.30319\\" + exeName;
    if (GetFileAttributesW(frameworkPath.c_str()) != INVALID_FILE_ATTRIBUTES) return frameworkPath;

    return L"";
}

bool HasValidSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
    WinTrustData.pFile = &FileData;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return (lStatus == ERROR_SUCCESS);
}

bool IsMicrosoftFile(const std::wstring& filePath) {
    DWORD dwHandle;
    DWORD dwSize = GetFileVersionInfoSizeW(filePath.c_str(), &dwHandle);
    if (dwSize == 0) return false;

    std::vector<BYTE> versionInfo(dwSize);
    if (!GetFileVersionInfoW(filePath.c_str(), dwHandle, dwSize, versionInfo.data())) return false;

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;
    UINT cbTranslate;

    if (VerQueryValueW(versionInfo.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        for (unsigned int i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++) {
            wchar_t subBlock[256];
            swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
            wchar_t* companyName = nullptr;
            UINT len = 0;
            if (VerQueryValueW(versionInfo.data(), subBlock, (LPVOID*)&companyName, &len)) {
                if (companyName) {
                    std::wstring company(companyName);
                    if (company.find(L"Microsoft") != std::wstring::npos) return true;
                }
            }
        }
    }
    return false;
}

bool IsIgnoredName(const std::wstring& name) {
    static std::set<std::wstring> whitelist = {
        L"CL.EXE", L"LINK.EXE", L"RC.EXE", L"DUMPBIN.EXE", L"TRACKER.EXE", L"MSBUILD.EXE", L"VCPKGSRV.EXE",
        L"MOUSOCOREWORKER.EXE", L"USOCLIENT.EXE", L"CONHOST.EXE", L"CMD.EXE", L"REPLACEPARSER.EXE",
        L"SEARCHFILTERHOST.EXE", L"SEARCHPROTOCOLHOST.EXE", L"WMIPRVSE.EXE", L"SVCHOST.EXE", L"TASKHOSTW.EXE",
        L"SFCHECK.EXE", L"BACKGROUNDDOWNLOAD.EXE", L"FILECOAUTH.EXE", L"GPU_ENCODER_HELPER.EXE",
        L"MICROSOFT.SERVICEHUB.CONTROLLER.EXE", L"OPENCONSOLE.EXE", L"SNIPPINGTOOL.EXE",
        L"UPDATE.EXE", L"WINDOWSTERMINAL.EXE"
    };
    std::wstring shortName = name;
    size_t slashPos = name.find_last_of(L"\\/");
    if (slashPos != std::wstring::npos) shortName = name.substr(slashPos + 1);
    return whitelist.find(shortName) != whitelist.end();
}


void CheckAndPrint(std::wstring exeName, std::wstring fullPath, FILETIME ftLastRun, std::string source) {
    if (exeName.empty()) return;

    std::wstring trimCheck = exeName;
    trimCheck.erase(std::remove(trimCheck.begin(), trimCheck.end(), L' '), trimCheck.end());
    if (trimCheck.empty()) return;

    std::wstring upperName = exeName;
    std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::towupper);

    if (g_ReportedFiles.find(upperName) != g_ReportedFiles.end()) return;

    static std::set<std::wstring> runningProcs = GetRunningProcesses();
    if (runningProcs.find(upperName) != runningProcs.end()) return;

    if (IsIgnoredName(upperName)) return;

    if (fullPath.empty()) fullPath = ResolvePath(exeName);

    bool isSafe = false;
    if (!fullPath.empty()) {
        if (HasValidSignature(fullPath)) isSafe = true;
        if (!isSafe && IsMicrosoftFile(fullPath)) isSafe = true;
    }

    if (isSafe) return;

    std::string timeStr = FileTimeToString(ftLastRun);
    std::wcout << L"[!] " << exeName;
    int spaces = 30 - exeName.length();
    if (spaces > 0) for (int i = 0; i < spaces; i++) std::cout << " ";
    std::cout << "| Last: " << timeStr << " (" << source << ")" << std::endl;

    g_ReportedFiles.insert(upperName);
}

void ScanClosedPrograms() {
    std::cout << "\n[SCANNER] Checking for suspicious CLOSED programs (Last 10 mins)..." << std::endl;
    std::cout << "-------------------------------------------------------------------" << std::endl;

    std::wstring path = L"C:\\Windows\\Prefetch\\*.pf";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(path.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (IsWithinLast10Minutes(fd.ftLastWriteTime)) {
                std::wstring filename = fd.cFileName;
                size_t dashPos = filename.find_last_of(L'-');
                if (dashPos != std::wstring::npos) {
                    std::wstring exeName = filename.substr(0, dashPos);
                    CheckAndPrint(exeName, L"", fd.ftLastWriteTime, "Prefetch");
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    HKEY hKeyBam;
    const char* bamPath = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, bamPath, 0, KEY_READ, &hKeyBam) == ERROR_SUCCESS) {
        char sidKey[256];
        DWORD i = 0, len = 256;
        while (RegEnumKeyExA(hKeyBam, i++, sidKey, &len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::string fullPathKey = std::string(bamPath) + "\\" + std::string(sidKey);
            HKEY hKeyUser;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPathKey.c_str(), 0, KEY_READ, &hKeyUser) == ERROR_SUCCESS) {
                char valName[1024];
                DWORD valLen = 1024, j = 0, dataLen = 1024, type;
                BYTE data[1024];
                while (RegEnumValueA(hKeyUser, j++, valName, &valLen, NULL, &type, data, &dataLen) == ERROR_SUCCESS) {
                    if (type == REG_BINARY && dataLen == 24) {
                        FILETIME* ft = (FILETIME*)data;
                        if (IsWithinLast10Minutes(*ft)) {
                            std::string rawPath = valName;
                            size_t slashPos = rawPath.find_last_of('\\');
                            if (slashPos != std::string::npos) {
                                std::string fileNameStr = rawPath.substr(slashPos + 1);
                                std::wstring fileNameW(fileNameStr.begin(), fileNameStr.end());
                                CheckAndPrint(fileNameW, L"", *ft, "BAM");
                            }
                        }
                    }
                    valLen = 1024; dataLen = 1024;
                }
                RegCloseKey(hKeyUser);
            }
            len = 256;
        }
        RegCloseKey(hKeyBam);
    }

    if (g_ReportedFiles.empty()) {
        std::cout << "Clean. No suspicious closed programs found." << std::endl;
    }
}

void CheckLghubPrefetch() {
    std::cout << "\n[LGHUB] Checking history (Prefetch)..." << std::endl;
    std::wstring prefetchPath = L"C:\\Windows\\Prefetch\\LGHUB_AGENT.EXE*.pf";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(prefetchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cout << "LGHUB traces not found in Prefetch." << std::endl;
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
            std::cout << "LGHUB was last launched at: " << FileTimeToString(lastRunTime) << std::endl;
        }
    }
}

void ScanLghubMemory(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open LGHUB process. Run as Admin." << std::endl;
        return;
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
                    const char* targetStart = LGHUB_MACRO_STRING.c_str();
                    const char* targetEnd = targetStart + LGHUB_MACRO_STRING.length();

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
}

int main() {
    SetConsoleTitleW(L"SFCheck - Combined Scanner");
    std::cout << "Starting SFCheck..." << std::endl;

    DWORD pid = GetProcessIdByName(L"lghub_agent.exe");
    if (pid == 0) {
        std::cout << "LGHUB Agent not running." << std::endl;
        CheckLghubPrefetch();
        std::cout << "Result: Process is dead." << std::endl;
    }
    else {
        std::cout << "LGHUB Agent found (PID: " << pid << "). Scanning memory..." << std::endl;
        ScanLghubMemory(pid);
    }

    ScanClosedPrograms();

    std::cout << "\nFull scan complete." << std::endl;
    system("pause");
    return 0;
}
