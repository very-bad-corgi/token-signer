#include <utils.h>

#include <random>

void Utils::clearBuffer(void* buf, size_t size)
{
    if (!buf || size == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(buf);
    for (size_t i = 0; i < size; ++i)
        p[i] = 0;
}

bool Utils::str2wstr(UINT codePage, const std::string& src, std::wstring& dst)
{
    if (src.empty())
    {
        dst.clear();
        return true;
    }

    int len = MultiByteToWideChar(codePage, 0, src.c_str(),
                                  static_cast<int>(src.size()),
                                  nullptr, 0);
    if (len <= 0) return false;

    dst.resize(len);
    int res = MultiByteToWideChar(codePage, 0, src.c_str(),
                                  static_cast<int>(src.size()),
                                  &dst[0], len);
    return res == len;
}

void Utils::generateLabel(char* buf, unsigned long len)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (!buf || len == 0) return;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, sizeof(alphabet) - 2);

    for (unsigned long i = 0; i < len; ++i)
        buf[i] = alphabet[dist(gen)];
}

void Utils::generatePRNGBuffer(unsigned char* buf, unsigned long len)
{
    if (!buf || len == 0) return;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    for (unsigned long i = 0; i < len; ++i)
        buf[i] = static_cast<unsigned char>(dist(gen));
}

