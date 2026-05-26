#define ARGSHIT_IMPLEMENTATION
#include "ArgShit.h"

#define UNIPATCH_IMPLEMENTATION
#include "UniPatchEngine.h"

int main(int argc, char* argv[]) {
    ArgShit args(argv, argc);

    if (argc < 2 || args.contains("-h")) {
        std::cout << "Usage: UniPatch.exe <1337_file_path> [options]\n"
            << "\t-h\t\tDisplay this help screen\n"
            << "\t-nb\t\tDo not Backup Target\n"
            << "\t-r\t\tTreat addresses as file offsets\n"
            << "\t-f\t\tForce patch\n"
            << "\t-l\t\tLoader Mode: patch bytes in memory\n"
            << "\t-t <exe name>\tTarget exe\n"
            << "\t-la <number>\tLoad module attempts (default:2000)\n"
            << "\t-lw <number>\tWait between load attempts (default:1ms)\n"
            << "\t-pa <number>\tPatch check attempts (default:200)\n"
            << "\t-pw <number>\tWait between patch checks (default:1ms)\n";
        return 0;
    }

    UniPatch::PatchConfig config;
    
    // Map command line flags to engine configuration
    config.raw_offsets = args.contains("-r");
    config.loader_mode = args.contains("-l");
    config.no_backup = args.contains("-nb") || config.loader_mode; // loader mode implies no backup
    config.force_patch = args.contains("-f");

    if (args.contains("-t")) {
        args.parseArg("-t");
        config.target_exe = UniPatch::to_string(args.getString());
    }

    if (args.contains("-la")) { args.parseArg("-la"); config.load_attempts = args.getInt(); }
    if (args.contains("-lw")) { args.parseArg("-lw"); config.load_wait = args.getInt(); }
    if (args.contains("-pa")) { args.parseArg("-pa"); config.patch_attempts = args.getInt(); }
    if (args.contains("-pw")) { args.parseArg("-pw"); config.patch_wait = args.getInt(); }

    // Run the engine
    if (!UniPatch::Parse1337(args.getArg(1), config)) return -1;

    std::cout << "\nBeginning patching Process\n";
    bool success = config.loader_mode ? UniPatch::LaunchAndPatchMemory(config) : UniPatch::ApplyPatchesToDisk(config);
    std::cout << "Cleaning up...\nDone... Good Bye\n";

    return success ? 0 : -1;
}