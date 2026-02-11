#ifndef CRYPTOOPERATIONS_H
#define CRYPTOOPERATIONS_H

#include <vector>
#include <string>
#include <stdexcept>
#include <Windows.h> // For DWORD

// Custom exception to hold WinAPI error code
class winapi_error : public std::runtime_error {
private:
    DWORD last_error;
public:
    winapi_error(const std::string& what, DWORD error_code) 
        : std::runtime_error(what), last_error(error_code) {}

    DWORD get_error_code() const {
        return last_error;
    }
};

class CryptoOperations {
public:
    static std::vector<unsigned char> generateCMS(
        const std::vector<unsigned char>& dataToSign,
        const std::string& providerName,
        const std::string& containerName,
        const std::string& pin,
        const std::string& certPath
    );
};

#endif // CRYPTOOPERATIONS_H
