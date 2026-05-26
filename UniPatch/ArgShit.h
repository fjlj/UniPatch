/*
 * ArgShit - A simple command line argument parser
 * * HOW TO USE THIS LIBRARY:
 * * In EXACTLY ONE C++ source file, define ARGSHIT_IMPLEMENTATION
 * before including this header:
 * * #define ARGSHIT_IMPLEMENTATION
 * #include "ArgShit.h"
 * * In all other files, simply #include "ArgShit.h" without the define.
 */

#ifndef ARGSHIT_H
#define ARGSHIT_H

#include <string>
#include <sstream>
#include <codecvt>

 // -----------------------------------------------------------------------------
 // Declarations
 // -----------------------------------------------------------------------------

std::wstring to_wstring(std::string str);
std::string to_string(std::wstring str);
std::string leadingZero(uint64_t num);

class ArgShit {
private:
    char** argv;
    int argc;
    int i;
    std::wstring s;

public:
    ArgShit();
    ArgShit(char* _argv[], int _argc);
    ArgShit(char* _argv[], int _argc, const char* find);

    void parseArg(const char* find);
    char* getArg(int ind);
    bool contains(const char* test);
    int getInt();
    std::wstring getString();
};

#endif // ARGSHIT_H


// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

#ifdef ARGSHIT_IMPLEMENTATION

#include <cstring> // Required for strcmp, strlen

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

std::string leadingZero(uint64_t num) {
    std::stringstream stream;
    stream << (num < 16 ? "0" : "") << std::hex << (0xFF & num);
    return stream.str();
}

ArgShit::ArgShit() {
    this->i = 0;
    this->s = L"";
}

ArgShit::ArgShit(char* _argv[], int _argc, const char* find) {
    this->i = 0;
    this->s = L"";
    this->argv = _argv;
    this->argc = _argc;
    this->parseArg(find);
}

ArgShit::ArgShit(char* _argv[], int _argc) {
    this->i = 0;
    this->s = L"";
    this->argv = _argv;
    this->argc = _argc;
}

void ArgShit::parseArg(const char* find) {
    this->i = 0;
    this->s = L"";
    if (this->argc != 0 && this->argc > 3) {
        std::stringstream conv;
        for (int o = 2; o < this->argc; o++) {
            if (strcmp(this->argv[o], find) == 0 && (o + 1 < this->argc) && strlen(this->argv[o + 1]) > 0) {
                conv << this->argv[o + 1];
                conv >> this->i;
                this->s = to_wstring(conv.str());
            }
        }
    }
}

char* ArgShit::getArg(int ind) {
    if (ind < this->argc) {
        return this->argv[ind];
    }
    else {
        return 0;
    }
}

bool ArgShit::contains(const char* test) {
    if (this->argc != 0 && this->argc > 2) {
        for (int _i = 2; _i < this->argc; _i++) {
            if (strcmp(this->argv[_i], test) == 0)
                return true;
        }
        return false;
    }
    else {
        return false;
    }
}

int ArgShit::getInt()
{
    return this->i;
}

std::wstring ArgShit::getString()
{
    return this->s;
}

#endif // ARGSHIT_IMPLEMENTATION