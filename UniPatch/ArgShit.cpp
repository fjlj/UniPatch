#include "ArgShit.h"

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
