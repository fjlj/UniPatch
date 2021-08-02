// WorkingWithFiles.cpp : This file reads from the file supplied in the first argument, loads the contents of that file
// as a patch list and containing on its first line an executable name... specifically for the .1337 format of patch files
// exported from x64dbg and x32dbg.. finally this application will patch the target file with the supplied patched... 
// checking for a matching expected original byte (can be overridden by -f) to prevent patching files of incorrect version
// or plainly the wrong file all together.. due to the nature of patch files primarily being supplied for PE files...
// we load the PE and convert the Relative Virtual Addresses(supplied by x64dbg on export) to Physical File Offsets(PFO)
// for patching.. This can be overriden with -r if the supplied addresses happen to already be file offsets.
// 
// Frank Lewis - fjlj - 08/01/2021

#include <Windows.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

UINT64 rvaToPa(UINT64 offsetRVA, PIMAGE_NT_HEADERS peHeader, LPVOID lpFileBase) {
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

bool inArgs(char* argv[],int argc, const char* find) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i],find) == 0)
            return true;
    }
    return false;
}

struct PE_Stuff {
    //patch variables
    string PE_Name = "";
    UINT64 rva_offset[512], file_offset[512] = { 0 };
    UINT64 org_byte[512], rep_byte[512] = { 0 };
    int patch_count = 0;
    bool error = false;
};

void read1337(PE_Stuff *patch_info, char* argv[], int argc) {
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
    inFile.open(argv[1]);

    //if not able to open file fail with error
    if (!inFile.is_open()) {
        cout << "Could not open file " << argv[1] << endl;
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

            if (!inArgs(argv, argc, "-r") && peHeader != NULL && lpFileBase != NULL) {
                patch_info->file_offset[tmp_patch_count] = rvaToPa(patch_info->rva_offset[tmp_patch_count], peHeader, lpFileBase);
            }
            else
            {
                patch_info->file_offset[tmp_patch_count] = patch_info->rva_offset[tmp_patch_count];
            }
            //check that the RVA was found, converted to PFO, and we got the correct bytes for the patching
            if(!inArgs(argv, argc, "-r"))
                cout << "RVA: 0x" << std::hex << patch_info->rva_offset[tmp_patch_count] << " -> ";
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
            cout << "Patching File: " << patch_info->PE_Name << endl;
            if (!inArgs(argv, argc, "-r")) {

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


int main(int argc, char* argv[])
{

    //attempt to open in file
    if (!argv[1]) {
        cout << "Usage: UniPatch.exe <1337_file_path>";
        return -1;
    }
    PE_Stuff* to_patch = new PE_Stuff;
    read1337(to_patch,argv,argc);
    
    if (to_patch->error) {
        delete to_patch;
        return -1;
    }

    //variables for opening target
    fstream target;
    char o_byte[1];

    cout << "Read " << std::dec << to_patch->patch_count << " patches." << endl << endl << "Beginning patching Process" << endl;

    target.open(to_patch->PE_Name, std::ios_base::binary | std::ios_base::out | std::ios_base::in);
    if (!target.is_open()) {
        cout << "Unable to open target: " << to_patch->PE_Name << endl;
        delete to_patch;
        return -1;
    }

    for (int p = 0; p < to_patch->patch_count; p++) {
        
        cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & to_patch->file_offset[p]) << " Patch: 0x" << std::hex << (0xFF & to_patch->org_byte[p]) << "->0x" << std::hex << (0xFF & to_patch->rep_byte[p]) << endl;

        target.seekg(to_patch->file_offset[p]);
        target.read(o_byte, 1);
        cout << "Read byte: 0x" << std::hex << (0xFF & o_byte[0]) << endl;

        if (o_byte[0] != (char)to_patch->org_byte[p] && !inArgs(argv,argc,"-f")) {
            cout << "Original byte mismatch, perhaps already patched, or version differs, use -f to force patching. " << endl;
            delete to_patch;
            return -1;
        }

        target.seekp(to_patch->file_offset[p]);
        o_byte[0] = (char)to_patch->rep_byte[p];
        target.write(o_byte, 1);

        target.seekg(to_patch->file_offset[p]);
        target.read(o_byte, 1);
        cout << "Wrote byte: 0x" << std::hex << (0xFF & o_byte[0]) << endl << endl;
    }

    cout << "Patch complete!!!" << endl;

    //close files.
    if(target.is_open())
        target.close();

    cout << "Cleaning up..." << endl;
    delete to_patch;
    cout << "Done... Good Bye" << endl;
}
