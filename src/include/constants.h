#ifndef __CONSTANTS__H__
#define __CONSTANTS__H__

#include <vector>

namespace OIDS {
extern const std::vector<unsigned char> PKCS5_PBES2;
extern const std::vector<unsigned char> PKCS5_PBKDF2;
extern const std::vector<unsigned char> BELT_KEYWRAP;
extern const std::vector<unsigned char> HMAC_HBELT;
extern const std::vector<unsigned char> BIGN_PUBKEY;
extern const std::vector<unsigned char> BIGN_CURVE_256_V1;
extern const std::vector<unsigned char> BIGN_CURVE_384_V1;
extern const std::vector<unsigned char> BIGN_CURVE_512_V1;
extern const std::vector<unsigned char> ASN1_BIGN_CURVE_256_V1;
extern const std::vector<unsigned char> ASN1_BIGN_CURVE_384_V1;
extern const std::vector<unsigned char> ASN1_BIGN_CURVE_512_V1;

extern const std::vector<unsigned char> BELS_SHARE;
extern const std::vector<unsigned char> BELS_M0128_V1;
extern const std::vector<unsigned char> BELS_M0192_V1;
extern const std::vector<unsigned char> BELS_M0256_V1;

extern const std::vector<unsigned char> BELT_HASH256;
extern const std::vector<unsigned char> BASH256;
extern const std::vector<unsigned char> BASH384;
extern const std::vector<unsigned char> BASH512;

constexpr char HBELT_STR[] = "1.2.112.0.2.0.34.101.31.81";
constexpr char BIGN_PUBKEY_STR[] = "1.2.112.0.2.0.34.101.45.2.1";
constexpr char BIGN_SIGN_HBELT_STR[] = "1.2.112.0.2.0.34.101.45.12";
constexpr char BIGN_KEYTRANS_STR[] = "1.2.112.0.2.0.34.101.45.41";
constexpr char BIGN_CURVE_256_V1_STR[] = "1.2.112.0.2.0.34.101.45.3.1";
}

#endif // __CONSTANTS__H__

