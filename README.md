# UniPatch
A tool to parse *.1337 files (exported from x64dbg) and patch the target x86 or x64 file. Also supports "loader mode", where the file will be patched in memory at runtime rather than modifying the file. Loader mode supports supplying an EXE name with the -t flag (in the case that the *.1337 file targets a dll). Finally, loader mode allows argument options to modify the number of times to attempt and time between attempts, to read the module imageBase and the original bytes in memory (if the target is packed the original bytes may not be unpacked yet). 

```
Usage: UniPatch.exe <1337_file_path> [options]
        -h              Display this help screen
        -nb             Do not Backup Target
        -r              Treat addresses as file offsets
        -f              Force patch
        -l              Loader Mode: patch bytes in memory(no file modification) after launching target (implies -nb)
        -t <exe name>   Target exe (if unused defaults to target of 1337 file)
        -la <number>    Number of times to attempt to load Module data from memory (default:2000)
        -lw <number>    Number of miliseconds to wait between attempts (default:1)
        -pa <number>    Number of times to attempt to check original byte before patching (default:200)
        -pw <number>    Number of miliseconds to wait between checking original byte again (default:1)
```
