#ifndef UNIPATCH_ENGINE_H
#define UNIPATCH_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <codecvt>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include <psapi.h>

namespace UniPatch {

	struct PatchData {
		uint64_t rva_offset = 0;
		uint64_t file_offset = 0;
		uint8_t org_byte = 0;
		uint8_t rep_byte = 0;
	};

	struct ModulePatch {
		std::string target_name;
		std::vector<PatchData> patches;
	};

	struct PatchConfig {
		std::vector<ModulePatch> modules;

		// Timing parameters
		int load_attempts = 2000;
		int patch_attempts = 200;
		uint32_t load_wait = 1;
		uint32_t patch_wait = 1;

		// Engine operation flags
		bool raw_offsets = false; // -r
		bool loader_mode = false; // -l
		bool no_backup = false;   // -nb
		bool force_patch = false; // -f
		std::string target_exe = ""; // -t

		uint64_t getTotalPatches() const {
			uint64_t count = 0;
			for(const auto& mod : modules)
				count += mod.patches.size();
			return count;
		}
	};

	// Declarations
	std::wstring to_wstring(const std::string& str);
	std::string to_string(const std::wstring& str);
	std::string leadingZero(uint64_t num);

	// API no longer requires ArgShit
	bool Parse1337(const char* filepath, PatchConfig& config);
	bool ApplyPatchesToDisk(const PatchConfig& config);
	bool LaunchAndPatchMemory(const PatchConfig& config);
	bool ApplyPatchesInline(const PatchConfig& config);

} // namespace UniPatch

#endif // UNIPATCH_ENGINE_H


// ============================================================================
// IMPLEMENTATION
// ============================================================================

#ifdef UNIPATCH_IMPLEMENTATION

#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtSuspendProcess(IN HANDLE ProcessHandle);
EXTERN_C NTSTATUS NTAPI NtResumeProcess(IN HANDLE ProcessHandle);
constexpr auto SSUSP = 0x00000004;

namespace UniPatch {

	std::wstring to_wstring(const std::string& str) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
		return strconverter.from_bytes(str);
	}

	std::string to_string(const std::wstring& str) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
		return strconverter.to_bytes(str);
	}

	std::string leadingZero(uint64_t num) {
		std::stringstream stream;
		stream << (num < 16 ? "0" : "") << std::hex << (0xFF & num);
		return stream.str();
	}

	uint64_t rvaToPa(uint64_t offsetRVA, PIMAGE_NT_HEADERS peHeader, LPVOID lpFileBase) {
		PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peHeader);
		uint64_t nSectionCount = peHeader->FileHeader.NumberOfSections;
		uint64_t i = 0;
		for(i = 0; i <= nSectionCount; ++i, ++sectionHeader) {
			if((sectionHeader->VirtualAddress) > offsetRVA) {
				sectionHeader--; break;
			}
		}
		if(i > nSectionCount) {
			sectionHeader = IMAGE_FIRST_SECTION(peHeader);
			nSectionCount = peHeader->FileHeader.NumberOfSections;
			for(i = 0; i < nSectionCount - 1; ++i, ++sectionHeader);
		}
		uint64_t ret_addr = (uint64_t)((offsetRVA - (uint64_t)(sectionHeader->VirtualAddress) + (uint64_t)(sectionHeader->PointerToRawData)) + (uint64_t)(PBYTE)lpFileBase);
		return ((ret_addr <= (uint64_t)offsetRVA) ? ret_addr : (uint64_t)(ret_addr - (uint64_t)(PBYTE)lpFileBase));
	}

	bool Parse1337(const char* filepath, PatchConfig& config) {
		std::fstream inFile(filepath);
		if(!inFile.is_open()) {
			std::cout << "Could not open file " << filepath << std::endl;
			return false;
		}

		HANDLE hFile = NULL; HANDLE hFileMapping = NULL; LPVOID lpFileBase = NULL;
		PIMAGE_DOS_HEADER dosHeader = NULL; PIMAGE_NT_HEADERS peHeader = NULL;
		std::string lineRead; std::stringstream conv_me;
		size_t add_splitPos, byte_split;

		while(getline(inFile, lineRead)) {
			if(lineRead.empty()) continue;
			add_splitPos = lineRead.find(':');
			byte_split = lineRead.find('-');

			if(lineRead[0] == '>') {
				ModulePatch newMod;
				newMod.target_name = lineRead.substr(1, lineRead.length() - 1);
				config.modules.push_back(newMod);
				std::cout << "Target File: " << newMod.target_name << std::endl;

				if(!config.raw_offsets && !config.loader_mode) {
					std::cout << "Processing .1337 file RVA offsets..." << std::endl;
					hFile = CreateFileA(newMod.target_name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					if(hFile == INVALID_HANDLE_VALUE) {
						std::cout << "Unable to read file: " << newMod.target_name << std::endl;
						return false;
					}
					hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
					lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
					if(!lpFileBase) {
						std::cout << "MapViewOfFile failed" << std::endl;
						if(hFileMapping) CloseHandle(hFileMapping);
						if(hFile) CloseHandle(hFile);
						return false;
					}

					dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
					if(dosHeader != NULL && dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
						peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);
						if(peHeader->Signature != IMAGE_NT_SIGNATURE) {
							std::cout << "Did not find PE Signature" << std::endl;
							return false;
						}
					} else {
						std::cout << "Did not find DOS Signature" << std::endl;
						return false;
					}
				} else {
					std::cout << "Processing .1337 file as raw file offsets." << std::endl;
				}
			} else {
				if(config.modules.empty()) continue;
				PatchData patch;
				conv_me << std::hex << lineRead.substr(1, (add_splitPos - 1)).c_str();
				conv_me >> patch.rva_offset; conv_me.clear();
				conv_me << std::hex << lineRead.substr(add_splitPos + 1, byte_split - (add_splitPos + 1)).c_str();
				uint64_t tmpOrg;
				conv_me >> tmpOrg;
				patch.org_byte = (uint8_t)tmpOrg; conv_me.clear();
				conv_me << std::hex << lineRead.substr(byte_split + 2, lineRead.length() - (byte_split + 2)).c_str();
				uint64_t tmpRep;
				conv_me >> tmpRep;
				patch.rep_byte = (uint8_t)tmpRep;
				conv_me.clear();

				if(!config.raw_offsets && !config.loader_mode && peHeader != NULL && lpFileBase != NULL) {
					patch.file_offset = rvaToPa(patch.rva_offset, peHeader, lpFileBase);
				} else {
					patch.file_offset = patch.rva_offset;
				}

				if(!config.raw_offsets) 
					std::cout << "RVA: 0x" << std::hex << patch.rva_offset;
				if(!config.loader_mode && !config.raw_offsets) 
					std::cout << " --> PFO: 0x" << std::hex << patch.file_offset;
				else if(!config.loader_mode) 
					std::cout << " PFO: 0x" << std::hex << patch.file_offset;
				std::cout << " Patch: 0x" << leadingZero(patch.org_byte) << "->0x" << leadingZero(patch.rep_byte) << std::endl;

				config.modules.back().patches.push_back(patch);
			}
		}
		if(lpFileBase) UnmapViewOfFile(lpFileBase); 
		if(hFileMapping) CloseHandle(hFileMapping); 
		if(hFile) CloseHandle(hFile);
		inFile.close(); 
		return true;
	}

	bool ApplyPatchesToDisk(const PatchConfig& config) {
		std::fstream target; char o_byte[1];
		for(const auto& mod : config.modules) {
			if(!config.no_backup) CopyFileA(mod.target_name.c_str(), (mod.target_name + ".UniBak").c_str(), false);
			target.open(mod.target_name, std::ios_base::binary | std::ios_base::out | std::ios_base::in);
			if(!target.is_open()) {
				std::cout << "Unable to open target: " << mod.target_name << std::endl; 
				return false;
			}
			std::cout << "Module: " << mod.target_name << std::endl;

			for(const auto& patch : mod.patches) {
				std::cout << "Address: 0x" << std::hex << patch.file_offset << " Patch: 0x" << leadingZero(patch.org_byte) << "->0x" << leadingZero(patch.rep_byte) << std::endl;
				target.seekg((std::streamoff)patch.file_offset); target.read(o_byte, 1);

				if(o_byte[0] != (char)patch.org_byte && !config.force_patch) {
					std::cout << "Original byte mismatch. GOT: 0x" << leadingZero((uint64_t)o_byte[0]) << " Expected: 0x" << leadingZero(patch.org_byte) << "\nUse -f to force patching." << std::endl; 
					return false;
				}

				target.seekp((std::streamoff)patch.file_offset); o_byte[0] = (char)patch.rep_byte; target.write(o_byte, 1);
				target.seekg((std::streamoff)patch.file_offset); target.read(o_byte, 1);

				if(o_byte[0] != (char)patch.rep_byte) {
					std::cout << "Unable to write to address: 0x" << leadingZero(patch.file_offset) << std::endl; 
					return false;
				}
			}
			std::cout << mod.target_name << " - Patch complete!!!" << std::endl;
			if(target.is_open()) target.close();
		}
		return true;
	}

	uint64_t GetBaseAddress(PROCESS_INFORMATION process, WCHAR* name, int la, DWORD lw) {
		int attempts = 0; HMODULE hMods[1024]; DWORD cbNeeded; unsigned int i; bool snap_ret;
		while(attempts < la) {
			if(attempts % 100 == 0) std::cout << "Scanning... " << std::dec << (int)(((float)attempts / (float)la) * 100) << "%" << std::endl;
			ResumeThread(process.hThread); 
			snap_ret = K32EnumProcessModulesEx(process.hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL); 
			SuspendThread(process.hThread);
			if(snap_ret) {
				for(i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
					WCHAR szModName[MAX_PATH];
					if(K32GetModuleFileNameExW(process.hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
						if(wcsstr(szModName, name)) {
							std::cout << "MATCHED: " << to_string(szModName) << "\nBASE: 0x" << std::hex << hMods[i] << std::endl; 
							return (uint64_t)hMods[i];
						}
					}
				}
			}
			Sleep(lw); attempts++;
		}
		return 0;
	}

	bool LaunchAndPatchMemory(const PatchConfig& config) {
		if(config.modules.empty()) return false;

		std::wstring exe_name;
		if(!config.target_exe.empty()) {
			exe_name = to_wstring(config.target_exe);
		} else {
			exe_name = to_wstring(config.modules[0].target_name);
		}

		STARTUPINFOW sinfo = {sizeof(STARTUPINFOW)}; PROCESS_INFORMATION pinfo = {0};
		if(CreateProcessW(0, (LPWSTR)exe_name.c_str(), 0, 0, 0, SSUSP, 0, 0, &sinfo, &pinfo) == 0) {
			std::cout << "Unable to open target: " << to_string(exe_name) << std::endl; 
			return false;
		}

		DWORD oldProt; size_t w_bytes; char o_byte[1];
		for(const auto& mod : config.modules) {
			std::wstring patch_target = to_wstring(mod.target_name);
			uint64_t imgBase = GetBaseAddress(pinfo, (WCHAR*)patch_target.c_str(), config.load_attempts, config.load_wait);
			if(imgBase == 0) {
				std::cout << "Unable to determine ImageBase" << std::endl; TerminateProcess(pinfo.hProcess, 0); 
				return false;
			}

			for(const auto& patch : mod.patches) {
				VirtualProtectEx(pinfo.hProcess, (LPVOID)(imgBase + patch.file_offset), 0x01, PAGE_EXECUTE_READWRITE, &oldProt);
				int w_count = config.patch_attempts; bool b_test = false;
				do {
					NtResumeProcess(pinfo.hProcess); ReadProcessMemory(pinfo.hProcess, (LPCVOID)(imgBase + patch.file_offset), &o_byte, 1, &w_bytes);
					b_test = (o_byte[0] == (char)patch.org_byte); w_count--;
					if(!b_test) {
						Sleep(config.patch_wait); if(w_count % 20 == 0) std::cout << "Patch scanning... " << std::dec << (int)((float)(config.patch_attempts - w_count) / config.patch_attempts * 100.0f) << "%" << std::endl;
					}
					NtSuspendProcess(pinfo.hProcess);
				} while(!b_test && w_count > 0);

				if(!b_test && !config.force_patch) {
					std::cout << "Original byte not found. Use -f to force" << std::endl; TerminateProcess(pinfo.hProcess, 0); 
					return false;
				}
				o_byte[0] = (char)patch.rep_byte; WriteProcessMemory(pinfo.hProcess, (LPVOID)(imgBase + patch.file_offset), &o_byte, 1, &w_bytes);
				VirtualProtectEx(pinfo.hProcess, (LPVOID)(imgBase + patch.file_offset), 0x01, oldProt, &oldProt);
				std::cout << "Address: 0x" << std::hex << (imgBase + patch.file_offset) << " Patch: 0x" << leadingZero(patch.org_byte) << "->0x" << leadingZero(patch.rep_byte) << std::endl;
			}
		}
		NtResumeProcess(pinfo.hProcess); CloseHandle(pinfo.hProcess); CloseHandle(pinfo.hThread); 
		return true;
	}

	bool ApplyPatchesInline(const PatchConfig& config) {
		if(config.modules.empty()) return false;

		DWORD oldProt;

		for(const auto& mod : config.modules) {
			// Wait for the module to be loaded by the host process.
			HMODULE hModule = NULL;
			int attempts = 0;
			while(attempts < config.load_attempts) {
				hModule = GetModuleHandleA(mod.target_name.c_str());
				if(hModule != NULL) break;
				Sleep(config.load_wait);
				attempts++;
			}

			if(hModule == NULL) {
				std::cout << "Module " << mod.target_name << " not found in current process." << std::endl;
				return false;
			}

			uint64_t imgBase = (uint64_t)hModule;

			for(const auto& patch : mod.patches) {
				// In memory, sections aren't mapped as raw files, they are mapped by RVA.
				// Since our parser already sets file_offset = rva_offset when raw_offsets/loader_mode 
				// are active, we can just add it directly to the Image Base.
				void* targetAddr = (void*)(imgBase + patch.file_offset);

				VirtualProtect(targetAddr, 1, PAGE_EXECUTE_READWRITE, &oldProt);

				int w_count = config.patch_attempts;
				bool b_test = false;
				char current_byte = 0;

				// Wait loop in case the target uses a packer/crypter that hasn't decrypted the byte yet
				do {
					current_byte = *(char*)targetAddr; // Direct memory read!
					b_test = (current_byte == (char)patch.org_byte);
					w_count--;

					if(!b_test) {
						Sleep(config.patch_wait);
					}
				} while(!b_test && w_count > 0);

				if(!b_test && !config.force_patch) {
					std::cout << "Original byte not found at 0x" << std::hex << (uint64_t)targetAddr << ". Use force_patch to bypass." << std::endl;
					VirtualProtect(targetAddr, 1, oldProt, &oldProt);
					return false;
				}

				// Direct memory edit!
				*(char*)targetAddr = (char)patch.rep_byte;

				// Restore protection
				VirtualProtect(targetAddr, 1, oldProt, &oldProt);

				// CRITICAL FOR INLINE PATCHING: Flush the CPU instruction cache
				FlushInstructionCache(GetCurrentProcess(), targetAddr, 1);

				std::cout << "Inline Patched Address: 0x" << std::hex << (uint64_t)targetAddr
					<< " | 0x" << leadingZero(patch.org_byte) << "->0x" << leadingZero(patch.rep_byte) << std::endl;
			}
		}
		return true;
	}
} // namespace UniPatch
#endif // UNIPATCH_IMPLEMENTATION