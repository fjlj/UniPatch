// WorkingWithFiles.cpp : This file reads from the file supplied in the first argument, loads the contents of that file
// as a patch list and containing on its first line an executable name... specifically for the .1337 format of patch files
// exported from x64dbg and x32dbg.. finally this application will patch the target file with the supplied patched... 
// checking for a matching expected original byte (can be overridden by -f) to prevent patching files of incorrect version
// or plainly the wrong file all together.. due to the nature of patch files primarily being supplied for PE files...
// we load the PE and convert the Relative Virtual Addresses(supplied by x64dbg on export) to Physical File Offsets(PFO)
// for patching.. This can be overriden with -r if the supplied addresses happen to already be file offsets.
// -l for loader mode.. will load the target suspended, grab the base address, add the RVA to the base and patch the memory
// of the process at the given RVA in 1337 file. you can modify the wait time for attempting to get base or read original
// bytes before patching with -la -lw -pa -pw respectively. You are able to provide an alternate exe to launch with -t
// this allows targeting different modules within the program (presently only a single module is supported in 1337 parser)
// 
// Frank Lewis - fjlj - 08/01/2021

#include <Windows.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <tlhelp32.h> 
#include <codecvt>

#define SSUSP 0x00000004

using namespace std;

using convert_t = std::codecvt_utf8<wchar_t>;
std::wstring_convert<convert_t, wchar_t> strconverter;

std::wstring to_wstring(std::string str)
{
    return strconverter.from_bytes(str);
}

UINT64 rvaToPa(UINT64 offsetRVA, PIMAGE_NT_HEADERS peHeader, LPVOID lpFileBase, bool loader_mode=false) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peHeader);
    UINT64 nSectionCount = peHeader->FileHeader.NumberOfSections;
    UINT64 i = 0;
    for (i = 0; i <= nSectionCount; ++i, ++sectionHeader)
    {
        if ((sectionHeader->VirtualAddress) > offsetRVA)
        {
            sectionHeader--;
            break;
        }
    }

    if (i > nSectionCount)
    {
        sectionHeader = IMAGE_FIRST_SECTION(peHeader);
        UINT64 nSectionCount = peHeader->FileHeader.NumberOfSections;
        for (i = 0; i < nSectionCount - 1; ++i, ++sectionHeader);
    }
    UINT64 ret_addr = (UINT64)((offsetRVA - (UINT64)(sectionHeader->VirtualAddress) + (UINT64)(sectionHeader->PointerToRawData)) + (UINT64)(PBYTE)lpFileBase);
    return ((ret_addr <= (UINT64)offsetRVA) ? ret_addr : (UINT64)(ret_addr - (UINT64)(PBYTE)lpFileBase));

}

class ArgShit {
public:
    int i;
    wstring s;
    char** argv;
    int argc;


public:
    ArgShit(char* _argv[], int _argc, const char* find) {
        i = 0;
        s = L"";
        this->argv = _argv;
        this->argc = _argc;
        this->parseArg(find);
    }

    ArgShit(char* _argv[], int _argc) {
        i = 0;
        s = L"";
        this->argv = _argv;
        this->argc = _argc;
    }

    void parseArg(const char* find) {
        i = 0;
        s = L"";
        if (argc != 0 && argc > 3) {
            stringstream conv;
            for (int o = 2; o < argc; o++) {
                if (strcmp(argv[o], find) == 0 && (o + 1 < argc) && strlen(argv[o + 1]) > 0) {
                    conv << argv[o + 1];
                    conv >> i;
                    s = to_wstring(conv.str());
                }
            }
        }
    }

    bool contains(const char *test){
        if (argc != 0 && argc > 2) {
            for (int i = 2; i < argc; i++) {
                if (strcmp(argv[i], test) == 0)
                    return true;
            }
            return false;
        }
        else {
            false;
        }
    }

    bool operator< (const int other)
    {
        return this->i < other;
    }

    bool operator> (const int other) {
        return this->i > other;
    };


    ArgShit() {
        i = 0;
        s = L"";
    }

    ~ArgShit() {};

};


struct PE_Stuff {
    //patch variables
    string PE_Name = "";
    UINT64 rva_offset[512], file_offset[512] = { 0 };
    UINT64 org_byte[512], rep_byte[512] = { 0 };
    int patch_count = 0;
    bool error = false;
};

void read1337(PE_Stuff *patch_info, ArgShit& arg_shit) {
    //PE_Stuff *patch_info = new PE_Stuff;
    //PE Image variables
    HANDLE hFile = NULL;
    HANDLE hFileMapping = NULL;
    LPVOID lpFileBase = NULL;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS peHeader = NULL;

    //variables to hold file handle and to receive line data
    fstream inFile;
    string lineRead;
    inFile.open(arg_shit.argv[1]);

    //if not able to open file fail with error
    if (!inFile.is_open()) {
        cout << "Could not open file " << arg_shit.argv[1] << endl;
        patch_info->error = true;
        return;
    }

    //variables for state of loading 1337 file and getting RVAs and BYTES
    bool exe_line_read = false;
    std::stringstream conv_me;
    size_t add_splitPos, byte_split = 0;

    int tmp_patch_count = 0;

    while (getline(inFile, lineRead)) {

        //locate the :
        add_splitPos = lineRead.find(':');
        // locate the -
        byte_split = lineRead.find('-');

        //process the address and bytes if the exe name was found and loaded
        if (exe_line_read) {

            conv_me << std::hex << (lineRead.substr(1, (add_splitPos - 1)).c_str());
            //convert hex string temp to int
            conv_me >> patch_info->rva_offset[tmp_patch_count];
            conv_me.clear();

            conv_me << std::hex << (lineRead.substr(add_splitPos + 1, byte_split - (add_splitPos + 1)).c_str());
            //convert hex string temp to int
            conv_me >> patch_info->org_byte[tmp_patch_count];
            conv_me.clear();

            conv_me << std::hex << (lineRead.substr(byte_split + 2, lineRead.length() - (byte_split + 2)).c_str());
            //again do some conversions.... 
            conv_me >> patch_info->rep_byte[tmp_patch_count];
            conv_me.clear();

            if (!arg_shit.contains("-r") && !arg_shit.contains("-l") && peHeader != NULL && lpFileBase != NULL) {
                patch_info->file_offset[tmp_patch_count] = rvaToPa(patch_info->rva_offset[tmp_patch_count], peHeader, lpFileBase);
            }
            else
            {
                patch_info->file_offset[tmp_patch_count] = patch_info->rva_offset[tmp_patch_count];
            }
            //check that the RVA was found, converted to PFO, and we got the correct bytes for the patching
            if (!arg_shit.contains("-r")) {
                cout << "RVA: 0x" << std::hex << patch_info->rva_offset[tmp_patch_count];
                if (!arg_shit.contains("-l"))cout << " --> ";
            }
            if (!arg_shit.contains("-l"))
                cout << "PFO: 0x" << std::hex << patch_info->file_offset[tmp_patch_count];
            cout << " Patch: 0x" << std::hex << patch_info->org_byte[tmp_patch_count] << "->" << "0x" << std::hex << patch_info->rep_byte[tmp_patch_count] << endl;

            tmp_patch_count++;
            if (tmp_patch_count > 511) {
                cout << "512 patch limit reached!!!" << endl;
                patch_info->error = true;
                return;
            }

        }
        else {
            //get the target PE name from the 1337 file
            patch_info->PE_Name = lineRead.substr(1, lineRead.length());
            cout << "Target File: " << patch_info->PE_Name << endl;
            if (!arg_shit.contains("-r")) {

                cout << "Processing .1337 file RVA offsets, USE -r to treat addresses as file offsets." << endl;
                //get a handle to the file and open for reading...
                hFile = CreateFileA(patch_info->PE_Name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

                //exit if failed
                if (hFile == INVALID_HANDLE_VALUE)
                {
                    cout << "Unable to read file: " << patch_info->PE_Name << endl;
                    patch_info->error = true;
                    return;
                }

                //map the file to PE struct
                hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

                //exit if failed
                if (hFileMapping == 0)
                {
                    cout << "CreateFileMapping failed" << endl;
                    CloseHandle(hFile);
                    patch_info->error = true;
                    return;
                }

                //more mapping of file to read the file map
                lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

                //exit if failed
                if (lpFileBase == 0)
                {
                    cout << "MapViewOfFile failed" << endl;
                    CloseHandle(hFileMapping);
                    CloseHandle(hFile);
                    patch_info->error = true;
                    return;
                }

                //cast to a dos header
                dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;  //pointer to dos headers

                //check that the PE has the dos header (this is all used for RVA - physical offset calculation
                if (dosHeader != NULL && dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    cout << "DOS Signature (MZ) Matched" << endl;

                    //cast NT Header with pointer to PE/NT header
                    peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);

                    //Check that we have a valid PE
                    if (peHeader->Signature == IMAGE_NT_SIGNATURE)
                    {
                        cout << "PE Signature (PE) Matched" << endl;
                    }
                    else {
                        cout << "Did not find PE Signature" << endl;
                        patch_info->error = true;
                        return;
                    }
                }
                else {
                    cout << "Did not find DOS Signature" << endl;
                    patch_info->error = true;
                    return;
                }
            }
            else {
                cout << "Processing .1337 file as raw file offsets." << endl;
            }
            exe_line_read = true;

        }

    }

    patch_info->patch_count = tmp_patch_count;

    if (lpFileBase != NULL)
        UnmapViewOfFile(lpFileBase);
    if (hFileMapping != NULL)
        CloseHandle(hFileMapping);
    if (hFile != NULL)
        CloseHandle(hFile);

    inFile.close();
    
    return;
}

void downcase(WCHAR* str) {
    for (int i = 0; str[i] != '\0'; i+=2) {
        if (str[i] >= 0x41 && str[i] <= 0x5A) {
            str[i] = str[i] + 0x20;
        }
    }
}

UINT64 GetBaseAddress(DWORD dwPID, WCHAR* name, int la, int lw)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    WCHAR name2[128];
    wcscpy_s(name2, name);
    downcase(name2);
    int attempts = 0;

    while (hModuleSnap == INVALID_HANDLE_VALUE && attempts < la) {
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
        Sleep(lw);
        attempts++;
    }
    if (hModuleSnap == INVALID_HANDLE_VALUE || hModuleSnap == 0)
    {
        cout << "Failed to create snapshot of process modules..." << endl;
        return 0;
    }
    else 
    {
        attempts = 0;
    }

    me32.dwSize = sizeof(MODULEENTRY32);


    while (!Module32First(hModuleSnap, &me32) && attempts < la) {
        Sleep(lw);
        attempts++;
    }

    if (!Module32First(hModuleSnap, &me32))
    {
        cout << "Failed to read modules of process..." << endl;
        CloseHandle(hModuleSnap);
        return 0;
    }

    do
    {
        downcase(me32.szModule);
        if (wcsstr(me32.szModule, name2)) return((UINT64)me32.modBaseAddr);
    } while (Module32Next(hModuleSnap, &me32));
    
    if(hModuleSnap != INVALID_HANDLE_VALUE && hModuleSnap != 0)
        CloseHandle(hModuleSnap);
    
    return 0;
}

int main(int argc, char* argv[])
{

    ArgShit *argShit = new ArgShit(argv, argc);

    //TODO: update loader mode to take a processname (in the case that the target is a dll used by X process)
    if (argc < 2 || argShit->contains("-h")) {
        cout << "Usage: UniPatch.exe <1337_file_path> [options]" << endl
            << "\t-h\t\tDisplay this help screen" << endl
            << "\t-nb\t\tDo not Backup Target" << endl
            << "\t-r\t\tTreat addresses as file offsets" << endl
            << "\t-f\t\tForce patch" << endl
            << "\t-l\t\tLoader Mode: patch bytes in memory(no file modification) after launching target (implies -nb)" << endl
            << "\t-t <exe name>\tTarget exe (if unused defaults to target of 1337 file)" << endl
            << "\t-la <number>\tNumber of times to attempt to load Module data from memory (default:2000)" << endl
            << "\t-lw <number>\tNumber of miliseconds to wait between attempts (default:1)" << endl
            << "\t-pa <number>\tNumber of times to attempt to check original byte before patching (default:200)" << endl
            << "\t-pw <number>\tNumber of miliseconds to wait between checking original byte again (default:1)" << endl;
        return -1;
    }

    //get loader timing variables from args if supplied
    int load_attempts = 2000;
    int load_wait = 1;
    int patch_attempts = 200;
    int patch_wait = 1;

    if (argShit->contains("-la")) {
        argShit->parseArg("-la");
        load_attempts = (argShit > 0 ? argShit->i : load_attempts);
    }

    if (argShit->contains("-lw")) {
        argShit->parseArg("-lw");
        load_wait = (argShit > 0 ? argShit->i : load_wait);
    }

    if (argShit->contains("-pa")) {
        argShit->parseArg("-pa");
        patch_attempts = (argShit > 0 ? argShit->i : patch_attempts);
    }

    if (argShit->contains("-pw")) {
        argShit->parseArg("-pw");
        patch_wait = (argShit > 0 ? argShit->i : patch_wait);
    }


    //attempt to open and read 1337 file
    PE_Stuff* to_patch = new PE_Stuff;
    read1337(to_patch, *argShit);

    if (to_patch->error) {
        delete to_patch;
        return -1;
    }

    //variables for opening target
    fstream target;
    char o_byte[1];

    cout << "Read " << std::dec << to_patch->patch_count << " patches." << endl << endl << "Beginning patching Process" << endl;

    if (!argShit->contains("-l")) {
        //open target file

        if (!argShit->contains("-nb")) {
            CopyFileA(to_patch->PE_Name.c_str(), (to_patch->PE_Name + ".UniBak").c_str(), false);
        }

        target.open(to_patch->PE_Name, std::ios_base::binary | std::ios_base::out | std::ios_base::in);
        if (!target.is_open()) {
            cout << "Unable to open target: " << to_patch->PE_Name << endl;
            delete to_patch;
            return -1;
        }

        //apply patches to binary file
        for (int p = 0; p < to_patch->patch_count; p++) {

            cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & to_patch->file_offset[p])
                << " Patch: 0x" << std::hex << (0xFF & to_patch->org_byte[p]) << "->0x" << std::hex << (0xFF & to_patch->rep_byte[p]) << endl;

            //read the original byte from file
            target.seekg(to_patch->file_offset[p]);
            target.read(o_byte, 1);
            cout << "Read byte: 0x" << std::hex << (0xFF & o_byte[0]) << endl;

            //error if the original byte does not match expected byte, unless -f flag specified
            if (o_byte[0] != (char)to_patch->org_byte[p] && !argShit->contains("-f")) {
                cout << "Original byte mismatch, perhaps already patched, or version differs, use -f to force patching. " << endl;
                delete to_patch;
                return -1;
            }

            //patch the original byte with the new byte
            target.seekp(to_patch->file_offset[p]);
            o_byte[0] = (char)to_patch->rep_byte[p];
            target.write(o_byte, 1);

            //read the new byte from file to confirm written successfully
            target.seekg(to_patch->file_offset[p]);
            target.read(o_byte, 1);
            cout << "Wrote byte: 0x" << std::hex << (0xFF & o_byte[0]) << endl << endl;
        }

        cout << "Patch complete!!!" << endl;

        //close files.
        if (target.is_open())
            target.close();

    }
    else {
        //loader mode

        wstring target_name;
        wstring patch_target;
        if (argShit->contains("-t")) {
            argShit->parseArg("-t");
            target_name = argShit->s;
            patch_target = to_wstring(to_patch->PE_Name);
        }
        else {
            patch_target = target_name = to_wstring(to_patch->PE_Name);
        }

        //launch target as suspended process
        STARTUPINFO sinfo; 
        PROCESS_INFORMATION pinfo;
        memset(&sinfo, 0, sizeof(STARTUPINFO));
        memset(&pinfo, 0, sizeof(PROCESS_INFORMATION));
        sinfo.cb = sizeof(STARTUPINFO);
        DWORD oldProt;
        size_t w_bytes;
        int w_count = 200;
        UINT64 imgBase = 0;


        
        if (CreateProcessW(0, (LPWSTR)target_name.c_str(), 0, 0, 0, SSUSP, 0, 0, &sinfo, &pinfo) == 0) {
            cout << "Unable to open target: " << target_name.c_str() << endl;
            delete to_patch;
            return -1;
        }

       
        ResumeThread(pinfo.hThread);

        imgBase = GetBaseAddress(pinfo.dwProcessId, (LPWSTR)patch_target.c_str(), load_attempts, load_wait);

        if (imgBase == 0) {
            cout << "Unable to determine ImageBase During launch" << endl;
            delete to_patch;
            return -1;
        }

        for (int p = 0; p < to_patch->patch_count; p++) {
            cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & (imgBase + to_patch->file_offset[p]))
                << " Patch: 0x" << std::hex << (0xFF & to_patch->org_byte[p]) << "->0x" << std::hex << (0xFF & to_patch->rep_byte[p]) << endl;

            

            VirtualProtectEx(pinfo.hProcess,(LPVOID)(imgBase + to_patch->file_offset[p]), 0x01, PAGE_EXECUTE_READWRITE, &oldProt);
            o_byte[0] = -1;
            w_count = patch_attempts;
            while (o_byte[0] != (char)to_patch->org_byte[p] && w_count > 0) {
                ReadProcessMemory(pinfo.hProcess,  (LPCVOID)(imgBase+to_patch->file_offset[p]), &o_byte, 1, &w_bytes);
                w_count--;
                Sleep(patch_wait);
            }

            if (o_byte[0] != (char)to_patch->org_byte[p] && !argShit->contains("-f")) {
                cout << "Original byte: " << std::hex << (0xFF & to_patch->org_byte[p]) << " not found at address: " << std::hex << (0xFFFFFFFFFFFFFFFF & (imgBase+ to_patch->file_offset[p])) << "Got: " << std::hex << (0xFF & o_byte[0]) << endl;
                delete to_patch;
                return -1;
            }

            o_byte[0] = (char)to_patch->rep_byte[p];
            WriteProcessMemory(pinfo.hProcess, (LPVOID)(imgBase + to_patch->file_offset[p]), &o_byte, 1, &w_bytes);

            VirtualProtectEx(pinfo.hProcess, (LPVOID)(imgBase + to_patch->file_offset[p]), 0x01, oldProt, &oldProt);

        }


    }

    cout << "Cleaning up..." << endl;
    delete to_patch;
    cout << "Done... Good Bye" << endl;
}
