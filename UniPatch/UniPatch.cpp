// UniPatch.cpp : This application reads from the file supplied in the first argument, loads the contents of that file
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
// //PS: its a bloody mess in here... 
// 
// Frank Lewis - fjlj - 08/01/2021

#include <Windows.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <codecvt>
#include <psapi.h>


#define SSUSP 0x00000004

using namespace std;

std::wstring to_wstring(std::string str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
    return strconverter.from_bytes(str);
}

std::string to_string(std::wstring str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
    return strconverter.to_bytes(str);
}

string leadingZero (UINT64 num) {
        std::stringstream stream;
        stream << (num < 16 ? "0" : "") << std::hex << (0xFF & num);
    return stream.str();
}

void downcase(WCHAR* str) {
    for (int i = 0; str[i] != '\0'; i += 2) {
        if (str[i] >= 0x41 && str[i] <= 0x5A) {
            str[i] = str[i] + 0x20;
        }
    }
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

private:
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

     char* getArg(int ind) {
        if (ind < argc) {
            return argv[ind];
        }
        else {
            return 0;
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
            return false;
        }
    }

    ArgShit() {
        i = 0;
        s = L"";
    }

    ~ArgShit() {};

private:
    bool operator< (const int other)
    {
        return this->i < other;
    }

    bool operator> (const int other) {
        return this->i > other;
    };

};


struct PE_Stuff {
    //patch variables
    string PE_Name = "";
    UINT64 rva_offset[512], file_offset[512] = { 0 };
    UINT64 org_byte[512], rep_byte[512] = { 0 };
    string DLL_paths[512] = { "" };
    int patch_count = 0;
    int snap_wait = 0;
    int load_attempts = 2000;
    int load_wait = 1;
    int patch_attempts = 200;
    int patch_wait = 1;
    bool error = false;
};

void read1337(PE_Stuff *patch_info, ArgShit& arg_shit) {
    //TODO:support parsing multiple modules in the same 1337 file

    HANDLE hFile = NULL;
    HANDLE hFileMapping = NULL;
    LPVOID lpFileBase = NULL;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS peHeader = NULL;

    //variables to hold file handle and to receive line data
    fstream inFile;
    string lineRead;
    inFile.open(arg_shit.getArg(1));

    //if not able to open file fail with error
    if (!inFile.is_open()) {
        cout << "Could not open file " << arg_shit.getArg(1) << endl;
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
            cout << " Patch: 0x" << leadingZero(patch_info->org_byte[tmp_patch_count]) << "->" << "0x" << leadingZero(patch_info->rep_byte[tmp_patch_count]) << endl;

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
            if (!arg_shit.contains("-r") && !arg_shit.contains("-l")) {
                cout << "TEST: " << patch_info->DLL_paths[0] << endl;
                cout << "Processing .1337 file RVA offsets, USE -r to treat addresses as file offsets." << endl;
                //get a handle to the file and open for reading...
                hFile = CreateFileA((patch_info->DLL_paths[0] + patch_info->PE_Name).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

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
                cout << "Processing .1337 file as raw file offsets. (loader mode will calculate during launch)" << endl;
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


//Return the image base of given module name
UINT64 GetBaseAddress(PROCESS_INFORMATION process, WCHAR* name, int la, int lw)
{
    //a different approach that allows snapping very quickly between resume/suspend... much more reliable...
    int attempts = 0;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i, snap_ret;

    while (attempts < la) {
        if (attempts % 100 == 0) cout << "Scanning for Modules...: " << std::dec << ((float)attempts/(float)la)*100 << "%" << endl;

        // resume momentarily Get a list of all the modules in this process.
        ResumeThread(process.hThread);
        snap_ret = EnumProcessModulesEx(process.hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
        //suspend after snap.
        SuspendThread(process.hThread);
        if (snap_ret != 0)
        {
            for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                TCHAR szModName[MAX_PATH];
                if (GetModuleFileNameEx(process.hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
                {
                    // check for matching module, return its base if found...
                    if (wcsstr(szModName, name)) {
                        cout << "MATCHED:" << to_string(szModName) << endl << "BASE:0x" << std::hex << hMods[i] << endl;
                        return((UINT64)hMods[i]);
                    }
                }
            }
        }
        else {
            Sleep(lw);
            attempts++;
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{

    ArgShit *argShit = new ArgShit(argv, argc);

    //TODO: update loader mode to get 
    if (argc < 2 || argShit->contains("-h")) {
        cout << "Usage: UniPatch.exe <1337_file_path> [options]" << endl
            << "\t-h\t\tDisplay this help screen" << endl
            << "\t-nb\t\tDo not Backup Target" << endl
            << "\t-r\t\tTreat addresses as file offsets" << endl
            << "\t-f\t\tForce patch (ignore original bytes in patch mode)" << endl
            << "\t-l\t\tLoader Mode: patch bytes in memory(no file modification) after launching target (implies -nb)" << endl
            << "\t-t <exe name>\tTarget exe (if unused defaults to target of 1337 file)" << endl
            << "\t-la <number>\tNumber of times to attempt to load Module data from memory (default:2000)" << endl
            << "\t-lw <number>\tNumber of miliseconds to wait between attempts (default:1)" << endl
            << "\t-pa <number>\tNumber of times to attempt to check original byte before patching (default:200)" << endl
            << "\t-pw <number>\tNumber of miliseconds to wait between checking original byte again (default:1)" << endl;
        return -1;
    }

    PE_Stuff* patch_info = new PE_Stuff;

    //get loader timing variables from args if supplied

    if (argShit->contains("-la")) {
        argShit->parseArg("-la");
        patch_info->load_attempts = (argShit > 0 ? argShit->i : patch_info->load_attempts);
    }
 
    if (argShit->contains("-lw")) {
        argShit->parseArg("-lw");
        patch_info->load_wait = (argShit > 0 ? argShit->i : patch_info->load_wait);
    }

    if (argShit->contains("-pa")) {
        argShit->parseArg("-pa");
        patch_info->patch_attempts = (argShit > 0 ? argShit->i : patch_info->patch_attempts);
    }

    if (argShit->contains("-pw")) {
        argShit->parseArg("-pw");
        patch_info->patch_wait = (argShit > 0 ? argShit->i : patch_info->patch_wait);
    }

    //attempt to open and read 1337 file
    read1337(patch_info, *argShit);

    if (patch_info->error) {
        delete patch_info;
        delete argShit;
        return -1;
    }

    //variables for opening target
    fstream target;
    char o_byte[1];

    cout << "Read " << std::dec << patch_info->patch_count << " patches." << endl << endl << "Beginning patching Process" << endl;

    if (!argShit->contains("-l")) {
        //open target file

        if (!argShit->contains("-nb")) {
            CopyFileA(patch_info->PE_Name.c_str(), (patch_info->PE_Name + ".UniBak").c_str(), false);
        }

        target.open(patch_info->PE_Name, std::ios_base::binary | std::ios_base::out | std::ios_base::in);
        if (!target.is_open()) {
            cout << "Unable to open target: " << patch_info->PE_Name << endl;
            delete patch_info;
            delete argShit;
            return -1;
        }

        //apply patches to binary file
        for (int p = 0; p < patch_info->patch_count; p++) {

            cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & patch_info->file_offset[p])
                << " Patch: 0x" << leadingZero(patch_info->org_byte[p]) << "->0x" << leadingZero(patch_info->rep_byte[p]) << endl;

            //read the original byte from file
            target.seekg(patch_info->file_offset[p]);
            target.read(o_byte, 1);
            cout << "Read byte: 0x" << leadingZero(o_byte[0]) << endl;

            //error if the original byte does not match expected byte, unless -f flag specified
            if (o_byte[0] != (char)patch_info->org_byte[p] && !argShit->contains("-f")) {
                cout << "Original byte mismatch, perhaps already patched, or version differs, use -f to force patching. " << endl;
                delete patch_info;
                delete argShit;
                return -1;
            }

            //patch the original byte with the new byte
            target.seekp(patch_info->file_offset[p]);
            o_byte[0] = (char)patch_info->rep_byte[p];
            target.write(o_byte, 1);

            //read the new byte from file to confirm written successfully
            target.seekg(patch_info->file_offset[p]);
            target.read(o_byte, 1);
            cout << "Wrote byte: 0x" << leadingZero(o_byte[0]) << endl << endl;
        }

        cout << "Patch complete!!!" << endl;

        //close files.
        if (target.is_open())
            target.close();

    }
    else {
        //loader mode 
        //TODO:support multiple modules in one 1337 file... 

        wstring exe_name;
        wstring patch_target;
        if (argShit->contains("-t")) {
            argShit->parseArg("-t");
            exe_name = argShit->s;
            patch_target = to_wstring(patch_info->PE_Name);
        }
        else {
            patch_target = exe_name = to_wstring(patch_info->PE_Name);
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
        
        if (CreateProcessW(0, (LPWSTR)exe_name.c_str(), 0, 0, 0, SSUSP, 0, 0, &sinfo, &pinfo) == 0) {
            cout << "Unable to open target: " << exe_name.c_str() << endl;
            delete patch_info;
            delete argShit;
            return -1;
        }

        //snag the image base of the module once loaded. 
        imgBase = GetBaseAddress(pinfo, (WCHAR*)patch_target.c_str(), patch_info->load_attempts,patch_info->load_wait);

        if (imgBase == 0) {
            cout << "Unable to determine ImageBase During launch" << endl;
            delete patch_info;
            delete argShit;
            return -1;
        }

        for (int p = 0; p < patch_info->patch_count; p++) {
                  
            VirtualProtectEx(pinfo.hProcess,(LPVOID)(imgBase + patch_info->file_offset[p]), 0x01, PAGE_EXECUTE_READWRITE, &oldProt);
            o_byte[0] = -1;
            w_count = patch_info->patch_attempts;
            bool b_test = false;

            //do while is one iteration faster... at ending the loop
            do  {
                ReadProcessMemory(pinfo.hProcess,  (LPCVOID)(imgBase+patch_info->file_offset[p]), &o_byte, 1, &w_bytes);
                b_test = o_byte[0] == (char)patch_info->org_byte[p];
                w_count--;
                if (!b_test) {
                    Sleep(patch_info->patch_wait);
                    cout << "patch scanning... " << leadingZero(o_byte[0]) << "==" << leadingZero((char)patch_info->org_byte[p]) << ":" << b_test << ", " << std::dec << w_count << endl;
                }
            } while (!b_test || w_count > 0);

            //error and exit if original byte does not match and -f was not used.
            if (o_byte[0] != (char)patch_info->org_byte[p] && !argShit->contains("-f")) {
                cout << "Original byte: " << leadingZero(patch_info->org_byte[p])
                     << " not found at address: " << std::hex << (0xFFFFFFFFFFFFFFFF & (imgBase+ patch_info->file_offset[p])) 
                     << " Got: " << leadingZero(o_byte[0]) << endl;
                delete patch_info;
                delete argShit;
                return -1;
            }

            o_byte[0] = (char)patch_info->rep_byte[p];
            WriteProcessMemory(pinfo.hProcess, (LPVOID)(imgBase + patch_info->file_offset[p]), &o_byte, 1, &w_bytes);

            VirtualProtectEx(pinfo.hProcess, (LPVOID)(imgBase + patch_info->file_offset[p]), 0x01, oldProt, &oldProt);
            
            cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & (imgBase + patch_info->file_offset[p]))
                << " Patch: 0x" << leadingZero(patch_info->org_byte[p]) << "->0x" << leadingZero(patch_info->rep_byte[p]) << endl;

        }
        ResumeThread(pinfo.hThread);

    }

    cout << "Cleaning up..." << endl;
    delete patch_info;
    delete argShit;
    cout << "Done... Good Bye" << endl;
}
