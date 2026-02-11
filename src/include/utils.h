#pragma once

#include <string>
#include <vector>
#include <windows.h>

class Utils
{
public:
    static void clearBuffer(void* buf, size_t size);

    static bool str2wstr(UINT codePage, const std::string& src, std::wstring& dst);

    void generateLabel(char* buf, unsigned long len);
    void generatePRNGBuffer(unsigned char* buf, unsigned long len);
};

