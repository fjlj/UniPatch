// UniPatch.cpp : This application reads from the file supplied in the first argument, loads the
// contents of that file as a patch list and containing on its first line an executable name...
// specifically for the .1337 format of patch files exported from x64dbg and x32dbg.. finally this
// application will patch the target file with the supplied patched... checking for a matching
// expected original byte (can be overridden by -f) to prevent patching files of incorrect version
// or plainly the wrong file all together.. due to the nature of patch files primarily being
// supplied for PE files... we load the PE and convert the Relative Virtual Addresses(supplied by
// x64dbg on export) to Physical File Offsets(PFO) for patching.. This can be overriden with -r if
// the supplied addresses happen to already be file offsets.
// base and patch the memory of the process at the given RVA in 1337 file. you can modify the wait
// -l for loader mode.. will load the target suspended, grab the base address, add the RVA to the
// time for attempting to get base or read original bytes before patching with -la -lw -pa -pw
// respectively. You are able to provide an alternate exe to launch with -t this allows targeting
// different modules within the program (presently only a single module is supported in 1337 parser)
//
// //PS: its a bloody mess in here...
//
// Frank Lewis - fjlj - 08/01/2021

#include "ArgShit.h"
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <psapi.h>

#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtSuspendProcess(IN HANDLE ProcessHandle);
EXTERN_C NTSTATUS NTAPI NtResumeProcess(IN HANDLE ProcessHandle);

constexpr auto SSUSP = 0x00000004;

struct Module {
	uint64_t patch_count = 0;
	uint64_t rva_offset[512], file_offset[512] = { 0 };
	uint64_t org_byte[512], rep_byte[512] = { 0 };
	std::string PE_Name[FILENAME_MAX+1] = { "" };
};

struct PE_Stuff {
	//patch variables
	Module* mods = new Module[64];
	uint64_t total_patches = 0;
	int module_count = 0;
	int snap_wait = 0;
	int load_attempts = 2000;
	int patch_attempts = 200;
	DWORD load_wait = 1;
	DWORD patch_wait = 1;
	bool error = false;
	unsigned char padding[7] = { 0 };

	~PE_Stuff() {
		if (mods) delete[] mods;
		mods = nullptr;
	}
};

uint64_t rvaToPa(uint64_t offsetRVA, PIMAGE_NT_HEADERS peHeader, LPVOID lpFileBase){ //, bool loader_mode = false) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peHeader);
	uint64_t nSectionCount = peHeader->FileHeader.NumberOfSections;
	uint64_t i = 0;

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
		nSectionCount = peHeader->FileHeader.NumberOfSections;
		for (i = 0; i < nSectionCount - 1; ++i, ++sectionHeader);
	}

	uint64_t ret_addr = (uint64_t)((offsetRVA - (uint64_t)(sectionHeader->VirtualAddress) + (uint64_t)(sectionHeader->PointerToRawData)) + (uint64_t)(PBYTE)lpFileBase);

	return ((ret_addr <= (uint64_t)offsetRVA) ? ret_addr : (uint64_t)(ret_addr - (uint64_t)(PBYTE)lpFileBase));
}

//open, parse and store offsets/patches from *.1337 file
void read1337(PE_Stuff* patch_info, ArgShit& arg_shit) {
	//TODO: support parsing multiple modules in the same 1337 file

	//windows file junk...
	HANDLE hFile = NULL;
	HANDLE hFileMapping = NULL;
	LPVOID lpFileBase = NULL;
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS peHeader = NULL;

	//variables to hold file handle and to receive line data
	std::fstream inFile;
	std::string lineRead;
	inFile.open(arg_shit.getArg(1));

	//if not able to open file fail with error
	if (!inFile.is_open()) {
		std::cout << "Could not open file " << arg_shit.getArg(1) << std::endl;
		patch_info->error = true;
		return;
	}

	//variables for state of loading 1337 file and getting RVAs and BYTES
	//bool exe_line_read = false;
	std::stringstream conv_me;
	size_t add_splitPos, byte_split = 0;
	uint64_t tmp_patch_count = 0;
	int tmp_module_count = -1; //to be sure it matches when adding patches to each module 

	while (getline(inFile, lineRead)) {
		//locate the :
		add_splitPos = lineRead.find(':');
		// locate the -
		byte_split = lineRead.find('-');

		//process the address and bytes if the exe name was found and loaded
		if (lineRead[0] == '>') {
			
			//write patch count to completed module index and add patch_count to total_patches...
			//if we have been here before (first iterration is -1 at this point)
			if (tmp_module_count >= 0) {
				patch_info->mods[tmp_module_count].patch_count = tmp_patch_count;
				patch_info->total_patches += tmp_patch_count;
			}
			
			//increment module count, reset patch_count (will either be 0 already or we have already stored/counted it...
			tmp_module_count++;
			tmp_patch_count = 0;
			
			//get the target PE name from the 1337 file
			*patch_info->mods[tmp_module_count].PE_Name = lineRead.substr(1, lineRead.length());
			std::cout << "Target File: " << *patch_info->mods[tmp_module_count].PE_Name << std::endl;
			if (!arg_shit.contains("-r") && !arg_shit.contains("-l")) {
				std::cout << "Processing .1337 file RVA offsets, USE -r to treat addresses as file offsets." << std::endl;
				//get a handle to the file and open for reading...
				hFile = CreateFileA((*patch_info->mods[tmp_module_count].PE_Name).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

				//exit if failed
				if (hFile == INVALID_HANDLE_VALUE)
				{
					std::cout << "Unable to read file: " << *patch_info->mods[tmp_module_count].PE_Name << std::endl;
					patch_info->error = true;
					return;
				}

				//map the file to PE struct
				hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

				//exit if failed
				if (!hFileMapping)
				{
					std::cout << "CreateFileMapping failed" << std::endl;
					CloseHandle(hFile);
					patch_info->error = true;
					return;
				}

				//more mapping of file to read the file map
				lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

				//exit if failed
				if (!lpFileBase)
				{
					std::cout << "MapViewOfFile failed" << std::endl;
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
					std::cout << "DOS Signature (MZ) Matched" << std::endl;

					//cast NT Header with pointer to PE/NT header
					peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);

					//Check that we have a valid PE
					if (peHeader->Signature == IMAGE_NT_SIGNATURE)
					{
						std::cout << "PE Signature (PE) Matched" << std::endl;
					}
					else {
						std::cout << "Did not find PE Signature" << std::endl;
						patch_info->error = true;
						return;
					}
				}
				else {
					std::cout << "Did not find DOS Signature" << std::endl;
					patch_info->error = true;
					return;
				}
			}
			else {
				std::cout << "Processing .1337 file as raw file offsets. (loader mode will calculate during launch)" << std::endl;
			}
		}
		else {
			conv_me << std::hex << (lineRead.substr(1, (add_splitPos - 1)).c_str());
			//convert hex string temp to int
			conv_me >> patch_info->mods[tmp_module_count].rva_offset[tmp_patch_count];
			conv_me.clear();

			conv_me << std::hex << (lineRead.substr(add_splitPos + 1, byte_split - (add_splitPos + 1)).c_str());
			//convert hex string temp to int
			conv_me >> patch_info->mods[tmp_module_count].org_byte[tmp_patch_count];
			conv_me.clear();

			conv_me << std::hex << (lineRead.substr(byte_split + 2, lineRead.length() - (byte_split + 2)).c_str());
			//again do some conversions....
			conv_me >> patch_info->mods[tmp_module_count].rep_byte[tmp_patch_count];
			conv_me.clear();

			if (!arg_shit.contains("-r") && !arg_shit.contains("-l") && peHeader != NULL && lpFileBase != NULL) {
				patch_info->mods[tmp_module_count].file_offset[tmp_patch_count] = rvaToPa(patch_info->mods[tmp_module_count].rva_offset[tmp_patch_count], peHeader, lpFileBase);
			}
			else
			{
				patch_info->mods[tmp_module_count].file_offset[tmp_patch_count] = patch_info->mods[tmp_module_count].rva_offset[tmp_patch_count];
			}
			//check that the RVA was found, converted to PFO, and we got the correct bytes for the patching
			if (!arg_shit.contains("-r")) {
				std::cout << "RVA: 0x" << std::hex << patch_info->mods[tmp_module_count].rva_offset[tmp_patch_count];
				if (!arg_shit.contains("-l")) std::cout << " --> ";
			}

			if (!arg_shit.contains("-l"))
				std::cout << "PFO: 0x" << std::hex << patch_info->mods[tmp_module_count].file_offset[tmp_patch_count];

			std::cout << " Patch: 0x" << leadingZero(patch_info->mods[tmp_module_count].org_byte[tmp_patch_count]) << "->" 
					  << "0x" << leadingZero(patch_info->mods[tmp_module_count].rep_byte[tmp_patch_count]) << std::endl;

			tmp_patch_count++;
			if (tmp_patch_count > 511) {
				std::cout << "512 patch limit reached!!!" << std::endl;
				patch_info->error = true;
				return;
			}
		}
	}

	//store the last module loaded's patch count and add to total, also store module count+1.
	patch_info->mods[tmp_module_count].patch_count = tmp_patch_count;
	patch_info->total_patches += tmp_patch_count;
	patch_info->module_count = tmp_module_count+1;

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
uint64_t GetBaseAddress(PROCESS_INFORMATION process, WCHAR* name, int la, DWORD lw)
{
	//a different approach that allows snapping very quickly between resume/suspend... much more reliable...
	int attempts = 0;
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
	bool snap_ret;

	while (attempts < la) {
		if (attempts % 100 == 0) std::cout << "Scanning for Modules...: " << std::dec << (int)(((float)attempts / (float)la) * 100) << "%" << std::endl;

		// resume momentarily Get a list of all the modules in this process.
		ResumeThread(process.hThread);
		snap_ret = K32EnumProcessModulesEx(process.hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
		
		//suspend after snap.
		SuspendThread(process.hThread);

		//process valid snap...
		if (snap_ret)
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				//get full path + module name of modules in snap
				WCHAR szModName[MAX_PATH];
				if (K32GetModuleFileNameExW(process.hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR)))
				{
					// check for matching module, return its base if found...
					if (wcsstr(szModName, name)) {
						std::cout << "MATCHED:" << to_string(szModName) << std::endl << "BASE:0x" << std::hex << hMods[i] << std::endl;
						return((uint64_t)hMods[i]);
					}
				}
			}
		}
		//no valid snap, sleep supplied time in ms (default 1ms) and try snap again.
		else {
			Sleep(lw);
			attempts++;
		}
	}

	//module never found.
	return 0;
}

int main(int argc, char* argv[])
{
	//setup an argument handler and display usage if no/too few arguments supplied
	ArgShit* argShit = new ArgShit(argv, argc);

	if (argc < 2 || argShit->contains("-h")) {
		std::cout << "Usage: UniPatch.exe <1337_file_path> [options]" << std::endl
			<< "\t-h\t\tDisplay this help screen" << std::endl
			<< "\t-nb\t\tDo not Backup Target" << std::endl
			<< "\t-r\t\tTreat addresses as file offsets" << std::endl
			<< "\t-f\t\tForce patch (ignore original bytes in patch mode)" << std::endl
			<< "\t-l\t\tLoader Mode: patch bytes in memory(no file modification) after launching target (implies -nb)" << std::endl
			<< "\t-t <exe name>\tTarget exe (if unused defaults to target of 1337 file)" << std::endl
			<< "\t-la <number>\tNumber of times to attempt to load Module data from memory (default:2000)" << std::endl
			<< "\t-lw <number>\tNumber of miliseconds to wait between attempts (default:1)" << std::endl
			<< "\t-pa <number>\tNumber of times to attempt to check original byte before patching (default:200)" << std::endl
			<< "\t-pw <number>\tNumber of miliseconds to wait between checking original byte again (default:1)" << std::endl;
		return -1;
	}

	//make an instance of struct that holds patch information.
	PE_Stuff* patch_info = new PE_Stuff;

	
	//get loader timing variables from args if supplied (likely not ever needed)
	if (argShit->contains("-la")) {
		argShit->parseArg("-la");
		patch_info->load_attempts = (argShit != nullptr ? argShit->getInt() : patch_info->load_attempts);
	}

	if (argShit->contains("-lw")) {
		argShit->parseArg("-lw");
		patch_info->load_wait = (argShit != nullptr ? argShit->getInt() : patch_info->load_wait);
	}

	if (argShit->contains("-pa")) {
		argShit->parseArg("-pa");
		patch_info->patch_attempts = (argShit != nullptr ? argShit->getInt() : patch_info->patch_attempts);
	}

	if (argShit->contains("-pw")) {
		argShit->parseArg("-pw");
		patch_info->patch_wait = (argShit != nullptr ? argShit->getInt() : patch_info->patch_wait);
	}

	//attempt to open and parse 1337 file
	read1337(patch_info, *argShit);

	if (patch_info->error) {
		delete patch_info;
		delete argShit;
		return -1;
	}

	//variables for opening target
	std::fstream target;
	char o_byte[1];

	std::cout << "Read " << std::dec << patch_info->module_count << " modules, and " << patch_info->total_patches << " patches." << std::endl << std::endl << "Beginning patching Process" << std::endl;

	if (!argShit->contains("-l")) {
		//open target file

		for (int module_ind = 0; module_ind < patch_info->module_count; module_ind++) {

			if (!argShit->contains("-nb")) {
				CopyFileA((*patch_info->mods[module_ind].PE_Name).c_str(), (*patch_info->mods[module_ind].PE_Name + ".UniBak").c_str(), false);
			}

			target.open(*patch_info->mods[module_ind].PE_Name, std::ios_base::binary | std::ios_base::out | std::ios_base::in);
			if (!target.is_open()) {
				std::cout << "Unable to open target: " << *patch_info->mods[module_ind].PE_Name << std::endl;
				delete patch_info;
				delete argShit;
				return -1;
			}

			std::cout << "Module: " << *patch_info->mods[module_ind].PE_Name << std::endl;

			//apply patches to binary file
			for (uint64_t p = 0; p < patch_info->mods[module_ind].patch_count; p++) {
				std::cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & patch_info->mods[module_ind].file_offset[p])
					<< " Patch: 0x" << leadingZero(patch_info->mods[module_ind].org_byte[p]) << "->0x" << leadingZero(patch_info->mods[module_ind].rep_byte[p]) << std::endl;

				//read the original byte from file
				target.seekg((std::streamoff)patch_info->mods[module_ind].file_offset[p]);
				target.read(o_byte, 1);
				//std::cout << "Read byte: 0x" << leadingZero(o_byte[0]) << std::endl;

				//error if the original byte does not match expected byte, unless -f flag specified
				if (o_byte[0] != (char)patch_info->mods[module_ind].org_byte[p] && !argShit->contains("-f")) {
					std::cout << "Original byte mismatch, perhaps already patched, or version differs. GOT: 0x" << leadingZero((uint64_t)o_byte[0]) << " Expected: 0x" << leadingZero((uint64_t)(char)patch_info->mods[module_ind].org_byte[p])  << std::endl 
						      << "Use -f to force patching. " << std::endl;
					delete patch_info;
					delete argShit;
					return -1;
				}

				//patch the original byte with the new byte
				target.seekp((std::streamoff)patch_info->mods[module_ind].file_offset[p]);
				o_byte[0] = (char)patch_info->mods[module_ind].rep_byte[p];
				target.write(o_byte, 1);

				//read the new byte from file to confirm written successfully
				target.seekg((std::streamoff)patch_info->mods[module_ind].file_offset[p]);
				target.read(o_byte, 1);
				//I can't think of a situation other than invalid permissions or file in use that this would happen.
				//also I am pretty sure an error would have been thrown already...
				if (o_byte[0] != (char)patch_info->mods[module_ind].rep_byte[p]) {
					std::cout << "Unable to write byte 0x" << leadingZero((uint64_t)((char)patch_info->mods[module_ind].org_byte[p])) << " To address: 0x" << leadingZero(patch_info->mods[module_ind].file_offset[p]) << std::endl
							  << "Perhaps the file is in use, or you do not have permission to edit the file. " << std::endl;
					delete patch_info;
					delete argShit;
					return -1;
				}
			}

			std::cout << *patch_info->mods[module_ind].PE_Name << " - Patch complete!!!" << std::endl;

			//close files.
			if (target.is_open())
				target.close();
		}
	}
	else {
		//loader mode
		//TODO: support multiple modules in one 1337 file...

		std::wstring exe_name;
		std::wstring patch_target;

		//launch target as suspended process
		STARTUPINFOW sinfo;
		PROCESS_INFORMATION pinfo;
		memset(&sinfo, 0, sizeof(STARTUPINFOW));
		memset(&pinfo, 0, sizeof(PROCESS_INFORMATION));
		sinfo.cb = sizeof(STARTUPINFOW);
		DWORD oldProt;
		size_t w_bytes;
		int w_count = 200;
		int w_count_o = 200;
		uint64_t imgBase = 0;
		int mod_ind = 0;


		if (argShit->contains("-t")) {
			argShit->parseArg("-t");
			exe_name = argShit->getString();
		}
		else {
			exe_name = to_wstring(*patch_info->mods[0].PE_Name);
		}

		if (CreateProcessW(0, (LPWSTR)exe_name.c_str(), 0, 0, 0, SSUSP, 0, 0, &sinfo, &pinfo) == 0) {
			std::cout << "Unable to open target: " << exe_name.c_str() << std::endl;
			delete patch_info;
			delete argShit;
			return -1;
		}

		while (mod_ind < patch_info->module_count) {
				patch_target = to_wstring(*patch_info->mods[mod_ind].PE_Name);

			//snag the image base of the module once loaded.
			imgBase = GetBaseAddress(pinfo, (WCHAR*)patch_target.c_str(), patch_info->load_attempts, patch_info->load_wait);

			if (imgBase == 0) {
				std::cout << "Unable to determine ImageBase During launch" << std::endl;
				TerminateProcess(pinfo.hProcess, 0);
				delete patch_info;
				delete argShit;
				return -1;
			}

			for (uint64_t p = 0; p < patch_info->mods[mod_ind].patch_count; p++) {
				VirtualProtectEx(pinfo.hProcess, (LPVOID)(imgBase + patch_info->mods[mod_ind].file_offset[p]), 0x01, PAGE_EXECUTE_READWRITE, &oldProt);
				o_byte[0] = -1;
				w_count = patch_info->patch_attempts;
				w_count_o = w_count;
				bool b_test = false;

				//do while is one iteration faster... at ending the loop
				do {
					NtResumeProcess(pinfo.hProcess);
					ReadProcessMemory(pinfo.hProcess, (LPCVOID)(imgBase + patch_info->mods[mod_ind].file_offset[p]), &o_byte, 1, &w_bytes);
					b_test = o_byte[0] == (char)patch_info->mods[mod_ind].org_byte[p];
					w_count--;
					if (!b_test) {
						Sleep(patch_info->patch_wait);
						if (w_count % 20 == 0) std::cout << "Patch scanning... " << std::dec << (int)((float)(w_count_o-w_count)/(float)(w_count_o) * 100.0f) << "%" << std::endl;
					}
					NtSuspendProcess(pinfo.hProcess);
				} while (!b_test && w_count > 0);

				//error and exit if original byte does not match and -f was not used.
				if (!b_test && !argShit->contains("-f")) {
					std::cout << "Original byte: " << leadingZero(patch_info->mods[mod_ind].org_byte[p])
						<< " not found at address: " << std::hex << (0xFFFFFFFFFFFFFFFF & (imgBase + patch_info->mods[mod_ind].file_offset[p]))
						<< " Got: " << leadingZero((uint64_t)o_byte[0]) << ", Use -f to force patching anyway" << std::endl;
					TerminateProcess(pinfo.hProcess, 0);
					delete patch_info;
					delete argShit;
					return -1;
				}

				o_byte[0] = (char)patch_info->mods[mod_ind].rep_byte[p];

				WriteProcessMemory(pinfo.hProcess, (LPVOID)(imgBase + patch_info->mods[mod_ind].file_offset[p]), &o_byte, 1, &w_bytes);

				VirtualProtectEx(pinfo.hProcess, (LPVOID)(imgBase + patch_info->mods[mod_ind].file_offset[p]), 0x01, oldProt, &oldProt);

				std::cout << "Address: 0x" << std::hex << (0xFFFFFFFFFFFFFFFF & (imgBase + patch_info->mods[mod_ind].file_offset[p]))
					<< " Patch: 0x" << leadingZero(patch_info->mods[mod_ind].org_byte[p]) << "->0x" << leadingZero(patch_info->mods[mod_ind].rep_byte[p]) << std::endl;
			}
			mod_ind++;
		}
		NtResumeProcess(pinfo.hProcess);
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
	}

	std::cout << "Cleaning up..." << std::endl;
	delete patch_info;
	delete argShit;
	std::cout << "Done... Good Bye" << std::endl;
}