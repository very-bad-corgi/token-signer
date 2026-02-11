#include "cryptooperations.h"
#include "crypto-constants.h" // Using STB crypto constants
#include <utils.h>
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <iostream>

// Avest CSP Bel Pro (AvPass token)
#ifndef AVEST_CSP_TYPE
#define AVEST_CSP_TYPE 423
#endif
#ifndef KP_SIGNATURE_PIN
#define KP_SIGNATURE_PIN 2
#endif
static const wchar_t AVEST_CSP_NAME[] = L"Avest CSP Bel Pro";


// --- Definitions for Belarusian GOST (STB) ---
// Provider type for Avest CSP, if not in SDK
#ifndef PROV_GOST_2001_DH
#define PROV_GOST_2001_DH 75
#endif

// OID for belt-hash algorithm (STB 34.101.31-2011)
#ifndef szOID_BELT_HASH
#define szOID_BELT_HASH "1.2.112.0.2.0.1.1.1"
#endif

// --- Helper Functions ---

// RAII wrapper for HCRYPTPROV
class CryptProvHandle {
private:
    HCRYPTPROV hProv;
    BOOL bCallerFreeProv;
public:
    CryptProvHandle() : hProv(0), bCallerFreeProv(FALSE) {}
    ~CryptProvHandle() {
        if (hProv && bCallerFreeProv) {
            CryptReleaseContext(hProv, 0);
        }
    }
    HCRYPTPROV* p_hProv() { return &hProv; }
    HCRYPTPROV get() { return hProv; }
    BOOL* p_bCallerFreeProv() { return &bCallerFreeProv; }
};

// RAII wrapper for HCERTSTORE
class CertStoreHandle {
private:
    HCERTSTORE hStore;
public:
    CertStoreHandle(HCERTSTORE h = NULL) : hStore(h) {}
    ~CertStoreHandle() {
        if (hStore) {
            CertCloseStore(hStore, 0);
        }
    }
    HCERTSTORE get() { return hStore; }
    void set(HCERTSTORE h) { hStore = h; }
};

// RAII wrapper for PCCERT_CONTEXT
class CertContextHandle {
private:
    PCCERT_CONTEXT pCert;
public:
    CertContextHandle(PCCERT_CONTEXT p = NULL) : pCert(p) {}
    ~CertContextHandle() {
        if (pCert) {
            CertFreeCertificateContext(pCert);
        }
    }
    PCCERT_CONTEXT get() { return pCert; }
    PCCERT_CONTEXT* p_pCert() { return &pCert; }
    const PCCERT_CONTEXT* p_cpCert() const { return &pCert; }
    void set(PCCERT_CONTEXT p) { pCert = p; }
};


// Function to read a file into a vector of bytes
static std::vector<BYTE> readFile(const char* filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw winapi_error("Cannot open file: " + std::string(filename), 0);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw winapi_error("Cannot read file: " + std::string(filename), 0);
    }
    return buffer;
}

// Function to decode a PEM certificate file content to a CERT_CONTEXT
static PCCERT_CONTEXT decodePemCertificate(const std::vector<BYTE>& certFileContent) {
    DWORD cbBinary = 0;
    BOOL result = CryptStringToBinaryA(
        reinterpret_cast<const char*>(certFileContent.data()),
        certFileContent.size(),
        CRYPT_STRING_BASE64HEADER,
        NULL,
        &cbBinary,
        NULL,
        NULL
    );
    if (!result) {
        throw winapi_error("CryptStringToBinaryA failed to get size.", GetLastError());
    }

    std::vector<BYTE> certDecoded(cbBinary);
    result = CryptStringToBinaryA(
        reinterpret_cast<const char*>(certFileContent.data()),
        certFileContent.size(),
        CRYPT_STRING_BASE64HEADER,
        certDecoded.data(),
        &cbBinary,
        NULL,
        NULL
    );
    if (!result) {
        throw winapi_error("CryptStringToBinaryA failed to decode.", GetLastError());
    }

    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        certDecoded.data(),
        cbBinary
    );
    if (!pCertContext) {
        throw winapi_error("CertCreateCertificateContext failed.", GetLastError());
    }
    return pCertContext; // Caller must free this
}


// --- Main Implementation ---

std::vector<BYTE> CryptoOperations::generateCMS(
    const std::vector<BYTE>& dataToSign,
    const std::string& providerName,
    const std::string& containerName,
    const std::string& pin,
    const std::string& certPath)
{
    // RAII wrappers for automatic cleanup
    CryptProvHandle hCryptProv;
    CertStoreHandle hMyStore;
    CertContextHandle pFileCert;
    CertContextHandle pStoreCert;
    HCRYPTMSG hMsg = NULL;

    try {
        // 1. Load certificate from PEM file
        std::vector<BYTE> certFileContent = readFile(certPath.c_str());
        pFileCert.set(decodePemCertificate(certFileContent));
        DWORD dwKeySpec = AT_SIGNATURE;
        bool useAvPassPath = !containerName.empty() && !providerName.empty();

        if (useAvPassPath) {
            // AvPass path: use cert from file only, acquire context by container + Avest CSP
            std::wstring wContainerName, wProviderName;
            if (!Utils::str2wstr(CP_UTF8, containerName, wContainerName) || !Utils::str2wstr(CP_UTF8, providerName, wProviderName)) {
                throw winapi_error("Failed to convert container/provider name to wide string.", 0);
            }
            if (!CryptAcquireContextW(hCryptProv.p_hProv(), wContainerName.c_str(), wProviderName.c_str(), AVEST_CSP_TYPE, CRYPT_SILENT)) {
                throw winapi_error("Failed to acquire Avest CSP context by container name. Check token and container name.", GetLastError());
            }
            *hCryptProv.p_bCallerFreeProv() = TRUE;
            if (!pin.empty()) {
                std::vector<BYTE> pinBuf(pin.begin(), pin.end());
                if (pinBuf.empty() || pinBuf.back() != 0) pinBuf.push_back(0);
                if (!CryptSetProvParam(hCryptProv.get(), KP_SIGNATURE_PIN, pinBuf.data(), 0)) {
                    throw winapi_error("Failed to set signature PIN (AvPass). Check PIN and token.", GetLastError());
                }
            }
        } else {
            // Store path: find cert in MY store and acquire key from store
            hMyStore.set(CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY"));
            if (!hMyStore.get()) {
                throw winapi_error("Failed to open user's MY certificate store.", GetLastError());
            }
            pStoreCert.set(CertFindCertificateInStore(hMyStore.get(), X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, pFileCert.get(), NULL));
            if (!pStoreCert.get()) {
                throw winapi_error("Certificate not found in the user's MY store. Use container + provider + cert file for AvPass.", GetLastError());
            }
            if (!CryptAcquireCertificatePrivateKey(pStoreCert.get(), CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, NULL, hCryptProv.p_hProv(), &dwKeySpec, hCryptProv.p_bCallerFreeProv())) {
                throw winapi_error("Failed to acquire private key from certificate.", GetLastError());
            }
            if (!pin.empty() && !CryptSetProvParam(hCryptProv.get(), PP_SIGNATURE_PIN, reinterpret_cast<const BYTE*>(pin.c_str()), 0)) {
                throw winapi_error("Failed to set signature PIN.", GetLastError());
            }
        }

        // Prepare signing info (use file cert for AvPass path, store cert for store path)
        PCCERT_CONTEXT pSignerCert = useAvPassPath ? pFileCert.get() : pStoreCert.get();
        CMSG_SIGNER_ENCODE_INFO signerEncodeInfo = {0};
        signerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
        signerEncodeInfo.pCertInfo = pSignerCert->pCertInfo;
        signerEncodeInfo.hCryptProv = hCryptProv.get();
        signerEncodeInfo.dwKeySpec = dwKeySpec;
        // Use Belarusian belt-hash algorithm OID
        signerEncodeInfo.HashAlgorithm.pszObjId = szOID_BELT_HASH;
        signerEncodeInfo.pvHashAuxInfo = NULL;

        // 7. Add authenticated attributes (signing time)
        CRYPT_ATTRIBUTE authAttrs[1];
        FILETIME signingTime;
        GetSystemTimeAsFileTime(&signingTime);
        DWORD cbEncoded = 0;
        CryptEncodeObject(X509_ASN_ENCODING, szOID_RSA_signingTime, &signingTime, NULL, &cbEncoded);
        std::vector<BYTE> encodedTime(cbEncoded);
        CryptEncodeObject(X509_ASN_ENCODING, szOID_RSA_signingTime, &signingTime, encodedTime.data(), &cbEncoded);
        
        authAttrs[0].pszObjId = szOID_RSA_signingTime;
        authAttrs[0].cValue = 1;
        authAttrs[0].rgValue = new CRYPT_ATTR_BLOB[1];
        authAttrs[0].rgValue->cbData = cbEncoded;
        authAttrs[0].rgValue->pbData = encodedTime.data();
        
        signerEncodeInfo.cAuthAttr = 1;
        signerEncodeInfo.rgAuthAttr = authAttrs;

        // 8. Prepare message for encoding
        CERT_BLOB certBlob;
        certBlob.cbData = pSignerCert->cbCertEncoded;
        certBlob.pbData = pSignerCert->pbCertEncoded;

        CMSG_SIGNED_ENCODE_INFO signedEncodeInfo = {0};
        signedEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
        signedEncodeInfo.cSigners = 1;
        signedEncodeInfo.rgSigners = &signerEncodeInfo;
        signedEncodeInfo.cCertEncoded = 1;
        signedEncodeInfo.rgCertEncoded = &certBlob;
        signedEncodeInfo.rgCrlEncoded = NULL;

        // 9. Create the CMS message using the traditional method
        hMsg = CryptMsgOpenToEncode(
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0, // dwFlags
            CMSG_SIGNED,
            &signedEncodeInfo,
            NULL,
            NULL
        );
        if (!hMsg) {
            throw winapi_error("CryptMsgOpenToEncode failed.", GetLastError());
        }

        if (!CryptMsgUpdate(hMsg, dataToSign.data(), dataToSign.size(), TRUE)) {
            throw winapi_error("CryptMsgUpdate failed.", GetLastError());
        }

        // Get the size of the signed message
        DWORD cbSignedMessage = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, &cbSignedMessage)) {
            throw winapi_error("CryptMsgGetParam (for size) failed.", GetLastError());
        }

        std::vector<BYTE> signedMessage(cbSignedMessage);

        // Get the signed message data
        if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, signedMessage.data(), &cbSignedMessage)) {
            throw winapi_error("CryptMsgGetParam (for data) failed.", GetLastError());
        }

        // Cleanup allocated memory for attributes
        delete[] authAttrs[0].rgValue;

        CryptMsgClose(hMsg);
        hMsg = NULL;

        return signedMessage;

    } catch (const winapi_error& e) {
        if (hMsg) CryptMsgClose(hMsg);
        // RAII handles will do the rest of the cleanup
        std::cerr << "ERROR: " << e.what() << " WinAPI Error Code: " << e.get_error_code() << std::endl;
        return {}; // Return empty vector on failure
    }
}
