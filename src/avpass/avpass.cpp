#include <avpass.h>
#include <softtoken.h>
#include <utils.h>
#include "constants.h"

#include "avpass_p.h"
#include "hidapi.h"

#include <cstring>
#include <mutex>
#include <iostream>
#include <map>
#include <shared_mutex>
#include <array>
#include <algorithm>

#include <Windows.h>
#include <utility>

#pragma comment (lib,"setupapi.lib")

constexpr wchar_t AVEST_CSP_NAME[] = L"Avest CSP Bel Pro";
constexpr DWORD AVEST_CSP_TYPE = 423;
constexpr DWORD AVPASS_CIPHER_CTX_MAGIC = 0x41564358; // AVCX

inline constexpr unsigned short AVPASS_VID = 0xC1A5;
inline constexpr unsigned short AVPASS_PID = 0x0502;

/* эти ALG_ID могут быть получены с помощью вызова функции Utils::enumAlgs */
enum class AVEST_CSP_ALGID : ALG_ID
{
    BIGN_SIGN = 8254,
    BIGN_KEYEX = 8255,
    BELT_CIPHER = 26176,
    BELT_ANOTHER = 32819,
    HBELT = 32825,
    BELT_MAC = 32833
};

// Простейшая реализация NTCTW::finally для RAII-деинициализации
namespace NTCTW {
template <typename F>
struct FinalAction
{
    F f;
    ~FinalAction() { f(); }
};

template <typename F>
FinalAction<F> finally(F f)
{
    return FinalAction<F>{std::move(f)};
}
} // namespace NTCTW


struct KEY_CSP_CONTEXT
{
    HCRYPTPROV prov = 0;
    HCRYPTKEY key = 0;
    std::string container_id = "";
    std::wstring container_id_w = L"";
};

struct HASH_CSP_CONTEXT
{
    HCRYPTPROV prov = 0;
    /* несколько контекстов (например хэширования) могут ссылаться на один
     * хэндл провайдера, поэтому нужен счётчик ссылок, чтобы освобождать хэндл только 1 раз,
     * когда никто больше не использует этот хэндл
     */
    std::atomic<int> prov_ref;
};

struct AVPASS_SESSION
{
    bool is_user_authorized = false;
    std::mutex user_auth_mutex;
    std::map<unsigned long, KEY_CSP_CONTEXT> key_csp_list;
    std::shared_mutex key_csp_list_mutex;
    std::map<unsigned long, HASH_CSP_CONTEXT> hash_csp_list;
    std::shared_mutex hash_csp_list_mutex;
    std::map<std::vector<unsigned char>, HCRYPTKEY> cipher_key_list;
    std::shared_mutex cipher_key_list_mutex;

    std::vector<unsigned char> pin;

    ~AVPASS_SESSION()
    {
        for (auto& csp : key_csp_list) {
            if (csp.second.key) {
                CryptDestroyKey(csp.second.key);
            }
            if (csp.second.prov) {
                CryptReleaseContext(csp.second.prov, 0);
            }
        }
        for (auto& hash : hash_csp_list) {
            if (hash.second.prov) {
                CryptReleaseContext(hash.second.prov, 0);
            }
        }
        for (auto& key : cipher_key_list) {
            if (key.second) {
                CryptDestroyKey(key.second);
            }
        }
        Utils::clearBuffer(pin.data(), pin.size());
    }
};

struct AVPASS_HASH_CONTEXT
{
    unsigned long prov_handle = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    unsigned long hash_size = 0;
    bool is_mac_mode = false;
};

struct AVEST_PUBLIC_KEY_INFO
{
    DWORD magic;
    DWORD sec_level;
    unsigned char seed[8];
    unsigned char xy[64];
    unsigned char p[32];
    unsigned char a[32];
    unsigned char b[32];
    unsigned char q[32];
    unsigned char yg[32];
};

struct AVPASS_CIPHER_CONTEXT
{
    /* магическое число чтобы отличать контекст AvPass от SoftToken */
    DWORD magic = AVPASS_CIPHER_CTX_MAGIC;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    ALG_ID alg_id = 0;
    int enc_mode = 0;
    DWORD cipher_mode = 0;
    unsigned long key_len = 0;
    bool is_operation_init = false;
    std::vector<unsigned char> iv;
    SoftToken soft_token;
};

struct AVPASS_TRANSPORT_KEY_INFO
{
    ALG_ID keyex_algid;
    DWORD flag;
    unsigned char iv[16];
};

static int createKeyHandle(HCRYPTPROV hProv, const unsigned char* key_val, unsigned long key_len, HCRYPTKEY* hKey)
{
    if (key_len != 32) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    HCRYPTHASH hHash = 0;
    do {
        if (!CryptCreateHash(hProv, static_cast<ALG_ID>(AVEST_CSP_ALGID::HBELT), 0, 0, &hHash)) {
            break;
        }
        if (!CryptSetHashParam(hHash, HP_HASHVAL, key_val, 0)) {
            break;
        }
        if (!CryptDeriveKey(hProv, static_cast<ALG_ID>(AVEST_CSP_ALGID::BELT_CIPHER), hHash, 0, hKey)) {
            break;
        }
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hHash) {
        CryptDestroyHash(hHash);
    }
    return rv;
}

static int exportPublicKeyValue(HCRYPTKEY hKey, std::vector<unsigned char>& pub_value)
{
    DWORD temp = 0;
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, nullptr, &temp)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    std::vector<unsigned char> buf(temp);
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, buf.data(), &temp)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    if (buf.size() != (sizeof(AVEST_PUBLIC_KEY_INFO) + sizeof(PUBLICKEYSTRUC))) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    AVEST_PUBLIC_KEY_INFO* apki = reinterpret_cast<AVEST_PUBLIC_KEY_INFO*>(buf.data() + sizeof(PUBLICKEYSTRUC));
    pub_value.insert(pub_value.begin(), apki->xy, apki->xy + sizeof(apki->xy));
    return NTCTW_ERRORS::SUCCESS;
}

AvpassPrivate::AvpassPrivate()
{

}

AvpassPrivate::~AvpassPrivate()
{

}

int AvpassPrivate::loadFunctionList()
{
    /* нет необходимости загружать список функций, т.к. не использется динамическая библиотека */
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::initialize()
{
    if (session_) {
        session_.reset(nullptr);
    }
    session_ = std::unique_ptr<AVPASS_SESSION>(new AVPASS_SESSION());
    if (soft_token_) {
        soft_token_.reset(nullptr);
    }
    soft_token_ = std::unique_ptr<SoftToken>(new SoftToken());
    return soft_token_->initialize();
}

int AvpassPrivate::finalize()
{
    if (soft_token_) {
        soft_token_->finalize();
        soft_token_.reset(nullptr);
    }
    if (session_) {
        session_.reset(nullptr);
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::getSlotList(std::vector<unsigned long> &slot_list)
{
    if (hid_init() < 0) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }

    hid_device_info* devs = hid_enumerate(AVPASS_VID, AVPASS_PID);
    int i = 0;
    hid_device_info* next_dev = devs ? devs : nullptr;
    while (next_dev != nullptr) {
        if (next_dev->manufacturer_string != nullptr) {
            std::wstring wstdstring(devs->manufacturer_string, wcslen(devs->manufacturer_string));
            if (wstdstring != L"AVEST") {
                next_dev = next_dev->next;
                continue;
            }
        }
        if (next_dev->serial_number != nullptr) {
            std::wstring wstdstring(devs->serial_number, wcslen(devs->serial_number));
            devices_.push_back({wstdstring.begin(), wstdstring.end()});
        }

        next_dev = next_dev->next;
        slot_list.push_back(i);
        i++;
    }
    hid_free_enumeration(devs);

    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::getSlotNameById(unsigned long slot_id, std::vector<unsigned char> &slot_name)
{
    if (slot_id < devices_.size()) {
        slot_name = devices_.at(slot_id);
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::openSession(const unsigned long slot_id)
{
    (void)slot_id;
    int err = soft_token_->openSession(0);
    if (err != NTCTW_ERRORS::SUCCESS) {
        return err;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::closeSession()
{
    return soft_token_->closeSession();
}

int AvpassPrivate::resetToken(unsigned long slot_id, const unsigned char* so_pin, unsigned long so_pin_size, const std::string& label)
{
    (void)slot_id;
    (void)so_pin;
    (void)so_pin_size;
    (void)label;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::isAuthorized(const std::string &key_id)
{
    (void)key_id;
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    std::unique_lock<std::mutex> lock(session_->user_auth_mutex);
    return session_->is_user_authorized ? NTCTW_ERRORS::SUCCESS : NTCTW_ERRORS::USER_NOT_LOGGED_IN;
}

int AvpassPrivate::login(const NTCTW_USER_TYPE user_type, unsigned char *pin, unsigned long pin_size)
{
    (void) user_type;
//    int rv = NTCTW_ERRORS::OPERATION_FAILED;
//    HCRYPTPROV hProv = 0;
//    if (CryptAcquireContext(&hProv, L"", AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_SILENT)) {
//        std::vector<unsigned char> tmp(pin, pin + pin_size);
//        if (*std::prev(tmp.end()) != '\0') {
//            tmp.push_back('\0');
//        }
//        if (CryptSetProvParam(hProv, KP_SIGNATURE_PIN, pin, 0)) {
//            session_->pin = std::move(tmp);
//            std::unique_lock<std::mutex> lock(session_->user_auth_mutex);
//            session_->is_user_authorized = true;
//            rv = NTCTW_ERRORS::SUCCESS;
//        } else {
//            rv = NTCTW_ERRORS::PASSWORD_INVALID;
//        }
//        CryptReleaseContext(hProv, 0);
//    }
//    return rv;
    std::vector<unsigned char> tmp(pin, pin + pin_size);
    if (*std::prev(tmp.end()) != '\0') {
        tmp.push_back('\0');
    }
    session_->pin = std::move(tmp);
    std::unique_lock<std::mutex> lock(session_->user_auth_mutex);
    session_->is_user_authorized = true;
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::logout()
{

    return NTCTW_ERRORS::SUCCESS;
}

unsigned long AvpassPrivate::getHashContextSize()
{
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::hashInit(void *hash_ctx, const NTCTW_HASH_ALG alg)
{
    ALG_ID alg_id = 0;
    unsigned long hash_size = 0;
    bool is_mac_mode = false;
    switch (alg) {
    case NTCTW_HASH_ALG::BELT_HASH256:
        alg_id = static_cast<ALG_ID>(AVEST_CSP_ALGID::HBELT);
        hash_size = 32;
        break;
    case NTCTW_HASH_ALG::BELT_MAC256:
        alg_id = static_cast<ALG_ID>(AVEST_CSP_ALGID::BELT_MAC);
        hash_size = 8;
        is_mac_mode = true;
        break;
    default:
        return NTCTW_ERRORS::UNSUPPORTED_ALGORITHM;
    }
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    AVPASS_HASH_CONTEXT hctx;
    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    do {
        if (!CryptAcquireContext(&hProv, L"", AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_VERIFYCONTEXT)) {
            break;
        }
        if (!is_mac_mode) {
            if (!CryptCreateHash(hProv, alg_id, 0, 0, &hHash)) {
                break;
            }
        }
        hctx.is_mac_mode = is_mac_mode;
        hctx.hHash = hHash;
        hHash = 0;
        hctx.hash_size = hash_size;

        std::unique_lock<std::shared_mutex> lock(session_->hash_csp_list_mutex);
        unsigned long prov_handle = getNewHashCspHandle();
        HASH_CSP_CONTEXT& csp_ctx = session_->hash_csp_list[prov_handle];
        csp_ctx.prov = hProv;
        hProv = 0;
        csp_ctx.prov_ref = 0;

        hctx.prov_handle = prov_handle;
        std::memcpy(hash_ctx, &hctx, sizeof(hctx));
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hHash) {
        CryptDestroyHash(hHash);
    }
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }
    return rv;
}

int AvpassPrivate::hashUpdate(void *hash_ctx, const unsigned char *data, const unsigned long size)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    AVPASS_HASH_CONTEXT* ctx = static_cast<AVPASS_HASH_CONTEXT*>(hash_ctx);
    if (!data || !ctx) {
        return  NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    if (!CryptHashData(ctx->hHash, data, static_cast<DWORD>(size), 0)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::hashFinal(void *hash_ctx, unsigned char *buf, const unsigned long buf_size)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    AVPASS_HASH_CONTEXT* ctx = static_cast<AVPASS_HASH_CONTEXT*>(hash_ctx);
    if (!ctx) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    if (buf_size < ctx->hash_size || !buf) {
        return  NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    DWORD tmp = static_cast<DWORD>(buf_size);
    if (!CryptGetHashParam(ctx->hHash, HP_HASHVAL, buf, &tmp, 0)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::hashControl(void *hash_ctx, int param_type, void *param, unsigned long param_len)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    AVPASS_HASH_CONTEXT* ctx = static_cast<AVPASS_HASH_CONTEXT*>(hash_ctx);
    if (!ctx) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    switch(param_type)
    {
    case HASH_CTRL_SET_KEY:
    {
        if (!ctx->is_mac_mode) {
            return NTCTW_ERRORS::INVALID_PARAMETERS;
        }
        /* составляем key_id */
        std::vector<unsigned char> key_id(static_cast<unsigned char*>(param), static_cast<unsigned char*>(param) + 8);
        {
            std::shared_lock<std::shared_mutex> lock(session_->cipher_key_list_mutex);
            /* ищем по key_id хэндл ключа */
            if (session_->cipher_key_list.count(key_id) == 1) {
                /* ключ уже есть на токене */
                ctx->hKey = session_->cipher_key_list[key_id];
            }
            Utils::clearBuffer(key_id.data(), key_id.size());
        }
        std::shared_lock<std::shared_mutex> lock(session_->hash_csp_list_mutex);
        HASH_CSP_CONTEXT& csp_ctx = session_->hash_csp_list[ctx->prov_handle];
        if (ctx->hKey == 0) {
            /* ключа на токене нет, значит создаём новый из входных параметров */
            int rv = createKeyHandle(csp_ctx.prov, static_cast<unsigned char*>(param), param_len, &ctx->hKey);
            if (rv != NTCTW_ERRORS::SUCCESS) {
                return rv;
            }
        }
        if (!CryptCreateHash(csp_ctx.prov, static_cast<ALG_ID>(AVEST_CSP_ALGID::BELT_MAC), ctx->hKey, 0, &ctx->hHash)) {
            return NTCTW_ERRORS::OPERATION_FAILED;
        }
    }
    break;
    default:
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::hashCopy(void *hash_ctx_to, void *hash_ctx_from)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    AVPASS_HASH_CONTEXT* hash_to = static_cast<AVPASS_HASH_CONTEXT*>(hash_ctx_to);
    AVPASS_HASH_CONTEXT* hash_from = static_cast<AVPASS_HASH_CONTEXT*>(hash_ctx_from);
    if (hash_to && hash_from) {
        hash_to->prov_handle = hash_from->prov_handle;
        hash_to->hash_size = hash_from->hash_size;
        {
            std::unique_lock<std::shared_mutex> lock(session_->hash_csp_list_mutex);
            if (session_->hash_csp_list.count(hash_from->prov_handle) != 1) {
                return NTCTW_ERRORS::INVALID_PARAMETERS;
            }
            HASH_CSP_CONTEXT& csp_ctx = session_->hash_csp_list[hash_from->prov_handle];
            ++csp_ctx.prov_ref;
        }
        hash_to->hHash = hash_from->hHash;
//        if (!CryptDuplicateHash(hash_from->hHash, nullptr, 0, &hash_to->hHash)) {
//            return NTCTW_ERRORS::OPERATION_FAILED;
//        }
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::hashCleanup(void *hash_ctx)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    AVPASS_HASH_CONTEXT* ctx = static_cast<AVPASS_HASH_CONTEXT*>(hash_ctx);
    if (!ctx) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }

    std::unique_lock<std::shared_mutex> lock(session_->hash_csp_list_mutex);
    if (session_->hash_csp_list.count(ctx->prov_handle) != 1) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    HASH_CSP_CONTEXT& csp_ctx = session_->hash_csp_list[ctx->prov_handle];

    if (csp_ctx.prov_ref == 0) {
        if (!CryptDestroyHash(ctx->hHash)) {
            return NTCTW_ERRORS::OPERATION_FAILED;
        }
        if (ctx->hKey) {
            if (!CryptDestroyKey(ctx->hKey)) {
                return NTCTW_ERRORS::OPERATION_FAILED;
            }
        }
        if (!CryptReleaseContext(csp_ctx.prov, 0)) {
            return NTCTW_ERRORS::OPERATION_FAILED;
        }
    } else {
        --csp_ctx.prov_ref;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::enumKeys(bool is_private, std::vector<std::string> &keys)
{
    (void)is_private;
    HCRYPTPROV hProv = 0;
    int  rv = NTCTW_ERRORS::OPERATION_FAILED;

    auto _ = NTCTW::finally([&hProv](){
        if (hProv) {
            CryptReleaseContext(hProv, 0);
        }
    });
    if (!CryptAcquireContext(&hProv, L"", AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_VERIFYCONTEXT)) {
        return rv;
    }
    DWORD flags = CRYPT_FIRST;
    DWORD size = 0;
    while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, nullptr, &size, flags)) {
        if (size == 0) {
            return rv;
        }

        std::vector<unsigned char> buf(size);
        if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, buf.data(), &size, flags)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                return rv;
            }
            break;
        }

        // Обрезаем строку до первого нуля (контейнеры возвращаются как null-terminated строки)
        std::string container_name(reinterpret_cast<char*>(buf.data()));
        size_t null_pos = container_name.find('\0');
        if (null_pos != std::string::npos) {
            container_name.resize(null_pos);
        }
        keys.push_back(container_name);
        flags = 0;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::loadKey(const std::string &id, bool is_private, unsigned long *key_handle, unsigned long *sec_level)
{
    HCRYPTPROV hProv = 0;
    int  rv = NTCTW_ERRORS::OPERATION_FAILED;
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (!session_->is_user_authorized) {
        return NTCTW_ERRORS::USER_NOT_LOGGED_IN;
    }
    
    // Парсим префикс "label:" или "id:" если есть
    std::string container_name = id;
    size_t colon_pos = id.find(':');
    if (colon_pos != std::string::npos && colon_pos < id.length() - 1) {
        container_name = id.substr(colon_pos + 1);
    }
    
    if (container_name.empty())
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    
    if (!is_private) {
        /* может уже загружен личный ключ, тогда просто вернём хэндл на него */
        std::shared_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
        auto it =  std::find_if(session_->key_csp_list.begin(), session_->key_csp_list.end(),
                                [&container_name](std::pair<unsigned long, KEY_CSP_CONTEXT> const& item){
                return (item.second.container_id == container_name);
        });
        if (it != std::end(session_->key_csp_list)) {
            *key_handle = it->first;
            *sec_level = 128;
            return NTCTW_ERRORS::SUCCESS;
        }
    }
    do {
        std::wstring id_w;
        if (!Utils::str2wstr(CP_UTF8, container_name, id_w)) {
            break;
        }
        if (!CryptAcquireContext(&hProv, id_w.data(), AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_SILENT))
            break;
        if (!CryptSetProvParam(hProv, KP_SIGNATURE_PIN, session_->pin.data(), 0)) {
            rv = NTCTW_ERRORS::PASSWORD_INVALID;
            if (user_pin_tries_remain_ > 0) {
                --user_pin_tries_remain_;
            }
            break;
        }
        KEY_CSP_CONTEXT csp_ctx;
        csp_ctx.prov = hProv;
        csp_ctx.container_id = container_name;
        csp_ctx.container_id_w = id_w;
        hProv = 0;
        std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
        unsigned long handle = getNewKeyCspHandle();
        session_->key_csp_list[handle] = std::move(csp_ctx);
        *key_handle = handle;
        *sec_level = 128;
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }
    return rv;
}

int AvpassPrivate::enumCertificates(std::vector<std::string> &certs)
{
    (void)certs;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::loadCertificate(const std::string &id, unsigned char *cert_val, unsigned long *cert_size)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
//    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::sign(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
                        const unsigned char *tbs, const unsigned long tbs_len, unsigned char *out, size_t *out_len)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    (void)need_to_calc_hash;
    (void)tbs_len;
    ALG_ID alg_id = 0;
    switch (hash_alg) {
    case NTCTW_HASH_ALG::BELT_HASH256:
        alg_id = static_cast<ALG_ID>(AVEST_CSP_ALGID::HBELT);
        break;
    default:
        return NTCTW_ERRORS::UNSUPPORTED_ALGORITHM;
    }
    unsigned long sig_len = (sec_level * 3) / 8;
    if (!out) {
        *out_len = sig_len;
        return NTCTW_ERRORS::SUCCESS;
    }
    if (*out_len < sig_len) {
        return NTCTW_ERRORS::ERROR_BUFFER_TO_SMALL;
    }
    std::vector<unsigned char> sig(sig_len);

    std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
    if (session_->key_csp_list.count(key_handle) != 1) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    KEY_CSP_CONTEXT& csp_ctx = session_->key_csp_list[key_handle];
    HCRYPTHASH hHash = 0;
    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    do {
        if (!CryptCreateHash(csp_ctx.prov, alg_id, 0, 0, &hHash)) {
            break;
        }
        if (!CryptSetHashParam(hHash, HP_HASHVAL, tbs, 0)) {
            break;
        }
        DWORD tmp = static_cast<DWORD>(sig_len);
        if (!CryptSignHash(hHash, AT_SIGNATURE, nullptr, 0, sig.data(), &tmp)) {
            break;
        }
        std::reverse(sig.begin(), sig.end());
        std::memcpy(out, sig.data(), sig_len);
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hHash) {
        CryptDestroyHash(hHash);
    }
    return rv;
}

int AvpassPrivate::verify(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
                          const unsigned char *tbs, const unsigned long tbs_len, const unsigned char *sig, const unsigned long sig_len)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    (void)need_to_calc_hash;
    (void)tbs_len;
    (void)sec_level;
    ALG_ID alg_id = 0;
    switch (hash_alg) {
    case NTCTW_HASH_ALG::BELT_HASH256:
        alg_id = static_cast<ALG_ID>(AVEST_CSP_ALGID::HBELT);
        break;
    default:
        return NTCTW_ERRORS::UNSUPPORTED_ALGORITHM;
    }

    std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
    if (session_->key_csp_list.count(key_handle) != 1) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    KEY_CSP_CONTEXT& csp_ctx = session_->key_csp_list[key_handle];
    HCRYPTHASH hHash = 0;
    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    do {
        if (!CryptCreateHash(csp_ctx.prov, alg_id, 0, 0, &hHash)) {
            break;
        }
        if (!CryptSetHashParam(hHash, HP_HASHVAL, tbs, 0)) {
            break;
        }
        if (!csp_ctx.key) {
            if (!CryptGetUserKey(csp_ctx.prov, AT_SIGNATURE, &csp_ctx.key)) {
                break;
            }
        }
        std::vector<unsigned char> sig_tmp(sig, sig + sig_len);
        std::reverse(sig_tmp.begin(), sig_tmp.end());
        if (!CryptVerifySignature(hHash, sig, static_cast<DWORD>(sig_len), csp_ctx.key, nullptr, 0)) {
            break;
        }
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hHash) {
        CryptDestroyHash(hHash);
    }
    return rv;
}

int AvpassPrivate::encrypt(unsigned long key_handle, const unsigned char *in, size_t in_len,
                           const unsigned char *header, unsigned long header_len, unsigned char *out, size_t *out_len)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    HCRYPTKEY hPublicKey = 0;
    {
        std::shared_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
        if (session_->key_csp_list.count(key_handle) != 1) {
            return NTCTW_ERRORS::KEY_NOT_FOUND;
        }
        auto key_csp_ctx = session_->key_csp_list[key_handle];
        hPublicKey = key_csp_ctx.key;
    }
    std::vector<unsigned char> pub_value;
    int err = exportPublicKeyValue(hPublicKey, pub_value);
    if (err != NTCTW_ERRORS::SUCCESS) {
        return err;
    }
    unsigned long tmp_key_handle = 0;
    do {
        std::array<char, 8> label;
        Utils().generateLabel(label.data(), static_cast<unsigned long>(label.size()));
        err = soft_token_->createPublicKey("", std::string(label.data(), label.size()), true, 128,
                                           pub_value.data(), static_cast<unsigned long>(pub_value.size()), &tmp_key_handle);
        if (err != NTCTW_ERRORS::SUCCESS) {
            break;
        }
        err = soft_token_->encrypt(tmp_key_handle, in, in_len, header, header_len, out, out_len);
    } while (0);
    if (tmp_key_handle != 0) {
        soft_token_->destroyKey(tmp_key_handle);
    }
    return err;
}

int AvpassPrivate::decrypt(unsigned long key_handle, const unsigned char *in, size_t in_len,
                           const unsigned char *header, unsigned long header_len, unsigned char *out, size_t *out_len)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (!out) {
        *out_len = 32;
        return NTCTW_ERRORS::SUCCESS;
    }
    HCRYPTPROV hProv = 0;
    {
        std::shared_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
        if (session_->key_csp_list.count(key_handle) != 1) {
            return NTCTW_ERRORS::KEY_NOT_FOUND;
        }
        auto key_csp_ctx = session_->key_csp_list[key_handle];
        hProv = key_csp_ctx.prov;
    }
    BLOBHEADER blob_head = {
        SIMPLEBLOB, CUR_BLOB_VERSION, 0x0000, static_cast<ALG_ID>(AVEST_CSP_ALGID::BELT_CIPHER)
    };
    AVPASS_TRANSPORT_KEY_INFO atki;
    if (header_len != sizeof(atki.iv)) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    atki.keyex_algid = static_cast<ALG_ID>(AVEST_CSP_ALGID::BIGN_KEYEX);
    atki.flag = 1;
    std::memcpy(atki.iv, header, header_len);
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(BLOBHEADER) + sizeof(AVPASS_TRANSPORT_KEY_INFO) + in_len);
    buf.insert(buf.begin(), reinterpret_cast<unsigned char*>(&blob_head),  reinterpret_cast<unsigned char*>(&blob_head) + sizeof(blob_head));
    buf.insert(buf.end(), reinterpret_cast<unsigned char*>(&atki),  reinterpret_cast<unsigned char*>(&atki) + sizeof(atki));
    buf.insert(buf.end(), in, in + in_len);
    HCRYPTKEY hKey = 0;
    if (!CryptImportKey(hProv, buf.data(), static_cast<DWORD>(buf.size()), 0, 0, &hKey)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    Utils().generatePRNGBuffer(out, *out_len);
    /* составляем key_id */
    std::vector<unsigned char> key_id(out, out + 8);
    {
        std::shared_lock<std::shared_mutex> lock(session_->cipher_key_list_mutex);
        /* сохраняем по key_id хэндл ключа */
        session_->cipher_key_list[key_id] = hKey;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::deriveKey(unsigned long priv_key_handle, unsigned long peer_pub_key_handle,
                             unsigned char *derived_key, unsigned long derived_key_len)
{
    (void)priv_key_handle;
    (void)peer_pub_key_handle;
    (void)derived_key;
    (void)derived_key_len;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::createPublicKey(const std::string &id, const std::string &label, const bool is_ephemeral,
                                   const unsigned long sec_level, const unsigned char *value, const unsigned long size,
                                   unsigned long *key_handle)
{
    (void)id;
    (void)sec_level;
    int  rv = NTCTW_ERRORS::OPERATION_FAILED;
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    CERT_PUBLIC_KEY_INFO info;
    info.PublicKey.cbData = static_cast<DWORD>(size);
    info.PublicKey.pbData = const_cast<unsigned char*>(value);
    info.PublicKey.cUnusedBits = 0;
    info.Algorithm.pszObjId = const_cast<char*>(OIDS::BIGN_PUBKEY_STR);
    info.Algorithm.Parameters.cbData = static_cast<DWORD>(OIDS::ASN1_BIGN_CURVE_256_V1.size());
    info.Algorithm.Parameters.pbData = const_cast<unsigned char*>(OIDS::ASN1_BIGN_CURVE_256_V1.data());
    if (is_ephemeral) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        do {
            std::wstring label_w;
            if (!Utils::str2wstr(CP_UTF8, label, label_w)) {
                break;
            }
            if (!CryptAcquireContext(&hProv, label_w.data(), AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_VERIFYCONTEXT)) {
                break;
            }
            if (!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &info, &hKey)) {
                break;
            }
            KEY_CSP_CONTEXT csp_ctx;
            csp_ctx.prov = hProv;
            hProv = 0;
            csp_ctx.key = hKey;
            hKey = 0;
            csp_ctx.container_id = label;
            csp_ctx.container_id_w = std::move(label_w);
            std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
            unsigned long handle = getNewKeyCspHandle();
            session_->key_csp_list[handle] = std::move(csp_ctx);
            *key_handle = handle;
            rv = NTCTW_ERRORS::SUCCESS;
        } while (0);
        if (hKey) {
            CryptDestroyKey(hKey);
        }
        if (hProv) {
            CryptReleaseContext(hProv, 0);
        }
        return rv;
    } else {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
}

int AvpassPrivate::createPrivateKey(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level,
                                    const unsigned char *value, const unsigned long size, unsigned long *key_handle)
{
    (void)id;
    (void)label;
    (void)is_ephemeral;
    (void)sec_level;
    (void)value;
    (void)size;
    (void)key_handle;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::createCertificate(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned char *value,
                                     const unsigned long size)
{
    (void)id;
    (void)label;
    (void)is_ephemeral;
    (void)value;
    (void)size;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::comparePublicKeys(const unsigned long key_handle_one, const unsigned long key_handle_two, const unsigned long sec_level)
{
    (void)sec_level;
    int  rv = NTCTW_ERRORS::OPERATION_FAILED;
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    std::shared_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
    if (session_->key_csp_list.count(key_handle_one) != 1 ||
            session_->key_csp_list.count(key_handle_two) != 1) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    KEY_CSP_CONTEXT& csp_ctx_one = session_->key_csp_list[key_handle_one];
    KEY_CSP_CONTEXT& csp_ctx_two = session_->key_csp_list[key_handle_two];
    std::vector<unsigned char> pub_value_one;
    if (!csp_ctx_one.key) {
        if (!CryptGetUserKey(csp_ctx_one.prov, AT_SIGNATURE, &csp_ctx_one.key)) {
            return NTCTW_ERRORS::OPERATION_FAILED;
        }
    }
    if (!csp_ctx_two.key) {
        if (!CryptGetUserKey(csp_ctx_two.prov, AT_SIGNATURE, &csp_ctx_two.key)) {
            return NTCTW_ERRORS::OPERATION_FAILED;
        }
    }
    rv = exportPublicKeyValue(csp_ctx_one.key, pub_value_one);
    if (rv != NTCTW_ERRORS::SUCCESS) {
        return rv;
    }
    std::vector<unsigned char> pub_value_two;
    rv = exportPublicKeyValue(csp_ctx_two.key, pub_value_two);
    if (rv != NTCTW_ERRORS::SUCCESS) {
        return rv;
    }
    return (pub_value_one == pub_value_two) ? NTCTW_ERRORS::SUCCESS : NTCTW_ERRORS::KEYS_NOT_EQUAL;
}

int AvpassPrivate::generateKeyPair(const std::string &key_label, const unsigned long sec_level, const bool is_ephemeral,
                                   unsigned long *pub_key_handle, unsigned long *priv_key_handle)
{
    (void)sec_level;
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (is_ephemeral) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    do {
        std::wstring label_w;
        if (!Utils::str2wstr(CP_UTF8, key_label, label_w)) {
            break;
        }
        if (!CryptAcquireContext(&hProv, label_w.data(), AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_NEWKEYSET)) {
            break;
        }
        if (!CryptGenKey(hProv, static_cast<ALG_ID>(AVEST_CSP_ALGID::BIGN_SIGN), CRYPT_EXPORTABLE, &hKey)) {
            break;
        }
        KEY_CSP_CONTEXT csp_ctx;
        csp_ctx.prov = hProv;
        hProv = 0;
        csp_ctx.key = hKey;
        hKey = 0;
        csp_ctx.container_id = key_label;
        csp_ctx.container_id_w = std::move(label_w);
        std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
        unsigned long handle = getNewKeyCspHandle();
        session_->key_csp_list[handle] = std::move(csp_ctx);
        *priv_key_handle = handle;
        *pub_key_handle = handle;
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hKey) {
        CryptDestroyKey(hKey);
    }
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }
    return rv;
}

int AvpassPrivate::destroyKey(const unsigned long key_handle)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
    if (session_->key_csp_list.count(key_handle) != 1) {
        /* эта функция вызывается 2 раза - для личного и открытого ключа
         * но для avpass используется только 1 хэндл
         * поэтому считаем, что раз такого ключа нет, значит для этого хэндла функция уже вызывалась
         */
        return NTCTW_ERRORS::SUCCESS;
    }
    KEY_CSP_CONTEXT& csp_ctx = session_->key_csp_list[key_handle];
    if (!CryptDestroyKey(csp_ctx.key)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    if (!CryptReleaseContext(csp_ctx.prov, 0)) {
        return NTCTW_ERRORS::OPERATION_FAILED;
    }
    session_->key_csp_list.erase(key_handle);
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::destroyCertificate(const std::string& id)
{
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::getPublicKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    std::unique_lock<std::shared_mutex> lock(session_->key_csp_list_mutex);
    if (session_->key_csp_list.count(key_handle) != 1) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    KEY_CSP_CONTEXT& csp_ctx = session_->key_csp_list[key_handle];
    std::vector<unsigned char> pub_value;
    int err = exportPublicKeyValue(csp_ctx.key, pub_value);
    if (err != NTCTW_ERRORS::SUCCESS) {
        return err;
    }
    if (buf_size < pub_value.size()) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    std::memcpy(buf, pub_value.data(), pub_value.size());
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::getPrivateKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size)
{
    (void)key_handle;
    (void)buf;
    (void)buf_size;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::cipherInit(void **cipher_ctx, NTCTW_CIPHER_ALG cipher_algid, const unsigned char *key,
                              const unsigned long key_len, const unsigned char *iv, const unsigned long iv_len, int enc_mode)
{
    int  rv = NTCTW_ERRORS::OPERATION_FAILED;
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (enc_mode == 1) {
        /* для шифрования используем программную реализацию */
        return soft_token_->cipherInit(cipher_ctx, cipher_algid, key, key_len, iv, iv_len, enc_mode);
    }
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    AVPASS_CIPHER_CONTEXT* ctx = nullptr;
    do {
        if (*cipher_ctx) {
            ctx = static_cast<AVPASS_CIPHER_CONTEXT*>(*cipher_ctx);
        } else {
            ctx = new AVPASS_CIPHER_CONTEXT();
            switch (cipher_algid) {
            case NTCTW_CIPHER_ALG::BELT_CFB:
                ctx->alg_id = static_cast<ALG_ID>(AVEST_CSP_ALGID::BELT_CIPHER);
                ctx->cipher_mode = CRYPT_MODE_CFB;
                break;
            case NTCTW_CIPHER_ALG::BELT_CTR:
                ctx->alg_id = static_cast<ALG_ID>(AVEST_CSP_ALGID::BELT_CIPHER);
                break;
            default:
                rv = NTCTW_ERRORS::UNSUPPORTED_ALGORITHM;
                break;
            }
            if (rv == NTCTW_ERRORS::UNSUPPORTED_ALGORITHM) {
                break;
            }
            ctx->enc_mode = enc_mode;
            *cipher_ctx = ctx;
        }
        if (iv) {
            ctx->iv.clear();
            ctx->iv.insert(ctx->iv.begin(), iv, iv + iv_len);
        }
        if (key_len != 0) {
            ctx->key_len = key_len;
        }
        if (key) {
            /* составляем key_id */
            std::vector<unsigned char> key_id(key, key + 8);
            {
                std::shared_lock<std::shared_mutex> lock(session_->cipher_key_list_mutex);
                /* находим по key_id хэндл ключа шифрования */
                if (session_->cipher_key_list.count(key_id) != 1) {
                    /* если такого ключа нет, то импортируем его */
                    Utils::clearBuffer(key_id.data(), key_id.size());
                    Utils().generatePRNGBuffer(key_id.data(), key_id.size());
                    if (!CryptAcquireContext(&hProv, L"", AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_VERIFYCONTEXT)) {
                        break;
                    }
                    rv = createKeyHandle(hProv, key, key_len, &hKey);
                    if (rv != NTCTW_ERRORS::SUCCESS) {
                        break;
                    }
                    session_->cipher_key_list[key_id] = hKey;
                } else {
                    hKey = session_->cipher_key_list[key_id];
                }
            }
            if (ctx->cipher_mode != 0) {
                if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&ctx->cipher_mode), 0)) {
                    rv = NTCTW_ERRORS::OPERATION_FAILED;
                    break;
                }
            }
            if (!ctx->iv.empty()) {
                if (!CryptSetKeyParam(hKey, KP_IV, ctx->iv.data(), 0)) {
                    rv = NTCTW_ERRORS::OPERATION_FAILED;
                    break;
                }
            }
            ctx->hProv = hProv;
            ctx->hKey = hKey;
            hProv = 0;
            hKey = 0;
        }
        ctx->is_operation_init = true;
        ctx = nullptr;
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hKey) {
        CryptDestroyKey(hKey);
    }
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }
    if (ctx) {
        delete ctx;
    }
    return rv;
}

int AvpassPrivate::cipherControl(void *cipher_ctx, int param_type, void *param, unsigned long param_len)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (!cipher_ctx || !param) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    AVPASS_CIPHER_CONTEXT* ctx = static_cast<AVPASS_CIPHER_CONTEXT*>(cipher_ctx);
    if (ctx->magic != AVPASS_CIPHER_CTX_MAGIC) {
        return soft_token_->cipherControl(cipher_ctx, param_type, param, param_len);
    }
    int rv = NTCTW_ERRORS::SUCCESS;
    switch (param_type)
    {
    case CIPHER_CTRL_SET_IV:
        if (!param || param_len != 16) {
            return NTCTW_ERRORS::INVALID_PARAMETERS;
        }
        ctx->iv.clear();
        ctx->iv.insert(ctx->iv.begin(), static_cast<unsigned char*>(param), static_cast<unsigned char*>(param) + param_len);
        break;
    case CIPHER_CTRL_RAND_KEY:
    {
        if (ctx->enc_mode == 0) {
            /* зачем генерировать случайный ключ при расшифровке, OpenSSL? */
            return NTCTW_ERRORS::SUCCESS;
        }
        if (!param || (ctx->key_len == 0)) {
            return NTCTW_ERRORS::INVALID_PARAMETERS;
        }

        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        rv = NTCTW_ERRORS::OPERATION_FAILED;
        do {
            if (!CryptAcquireContext(&hProv, L"", AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_VERIFYCONTEXT)) {
                break;
            }
            if (!CryptGenKey(hProv, ctx->alg_id, CRYPT_EXPORTABLE, &hKey)) {
                break;
            }
            if (ctx->cipher_mode != 0) {
                if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&ctx->cipher_mode), 0)) {
                    rv = NTCTW_ERRORS::OPERATION_FAILED;
                    break;
                }
            }
            if (!ctx->iv.empty()) {
                if (!CryptSetKeyParam(hKey, KP_IV, ctx->iv.data(), 0)) {
                    rv = NTCTW_ERRORS::OPERATION_FAILED;
                    break;
                }
            }
            /* т.к. ключ должен генерироваться на токене и не может его покаидать в открытом виде,
             * то генерируем ключ здесь, а входной параметр param будем использовтаь как id ключа
             * в функции транспорта ключа (encrypt)
             */
            Utils().generatePRNGBuffer(static_cast<unsigned char*>(param), ctx->key_len);
            std::vector<unsigned char> key_id(static_cast<unsigned char*>(param), static_cast<unsigned char*>(param) + 8);
            {
                std::unique_lock<std::shared_mutex> lock(session_->cipher_key_list_mutex);
                /* ставим в соответствие id ключа => хэнлд ключа
                 * и сохраняем в списке
                 * в дальнейшем при транспорте ключа из этого списка по id мы сможем получить хэндл ключа
                 */
                session_->cipher_key_list[key_id] = hKey;
            }
            ctx->hProv = hProv;
            ctx->hKey = hKey;
            hProv = 0;
            hKey = 0;
            rv = NTCTW_ERRORS::SUCCESS;
        } while (0);
        if (hKey) {
            CryptDestroyKey(hKey);
        }
        if (hProv) {
            CryptReleaseContext(hProv, 0);
        }
    }
    break;
    default:
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    return rv;
}

int AvpassPrivate::cipherDo(void *cipher_ctx, const unsigned char *in, unsigned long in_len, unsigned char *out)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (!cipher_ctx) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    AVPASS_CIPHER_CONTEXT* ctx = static_cast<AVPASS_CIPHER_CONTEXT*>(cipher_ctx);
    if (ctx->magic != AVPASS_CIPHER_CTX_MAGIC) {
        return soft_token_->cipherDo(cipher_ctx, in, in_len, out);
    }
    if (!ctx->is_operation_init) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    BOOL is_final = in ? FALSE : TRUE;
    std::vector<unsigned char> buf(in, in + in_len);
    DWORD bytes_processed = in_len;
    if (ctx->enc_mode == 1) {
        if (!is_final) {
            if (!CryptEncrypt(ctx->hKey, 0, is_final, 0, buf.data(), &bytes_processed, static_cast<DWORD>(in_len))) {
                return -1;
            }
        } else {
            buf.resize(32);
            if (!CryptEncrypt(ctx->hKey, 0, is_final, 0, buf.data(), &bytes_processed, 32)) {
                return -1;
            }
        }
        std::memcpy(out, buf.data(), bytes_processed);
    } else {
        if (!CryptDecrypt(ctx->hKey, 0, is_final, 0, buf.data(), &bytes_processed)) {
            return -1;
        }
        std::memcpy(out, buf.data(), bytes_processed);
    }
    Utils::clearBuffer(buf.data(), buf.size());
    return static_cast<int>(bytes_processed);
}

int AvpassPrivate::cipherCleanup(void *cipher_ctx)
{
    if (!session_) {
        return NTCTW_ERRORS::SESSION_HANDLE_INVALID;
    }
    if (!cipher_ctx) {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    AVPASS_CIPHER_CONTEXT* ctx = static_cast<AVPASS_CIPHER_CONTEXT*>(cipher_ctx);
    if (ctx->magic != AVPASS_CIPHER_CTX_MAGIC) {
        return soft_token_->cipherCleanup(cipher_ctx);
    }
    if (ctx->hKey) {
        CryptDestroyKey(ctx->hKey);
    }
    if (ctx->hProv) {
        CryptReleaseContext(ctx->hProv, 0);
    }
    delete ctx;
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::randAddEntropy(const unsigned char *buf, unsigned long size)
{
    (void)buf;
    (void)size;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::randBytes(unsigned char *buf, unsigned long size)
{
    int rv = NTCTW_ERRORS::OPERATION_FAILED;
    HCRYPTPROV hProv = 0;
    do {
        if (!CryptAcquireContext(&hProv, L"", AVEST_CSP_NAME, AVEST_CSP_TYPE, CRYPT_VERIFYCONTEXT)) {
            break;
        }
        if (!CryptGenRandom(hProv, static_cast<DWORD>(size), buf)) {
            break;
        }
        rv = NTCTW_ERRORS::SUCCESS;
    } while (0);
    if (hProv) {
        CryptReleaseContext(hProv, 0);
    }
    return rv;
}

void AvpassPrivate::randCleanup()
{
    return;
}

int AvpassPrivate::changePin(CHANGE_PIN_PAYLOD *change_pin_payload)
{
    (void)change_pin_payload;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::unblockPin(UNBLOCK_PIN_PAYLOAD *unblock_pin_payload)
{
    (void)unblock_pin_payload;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::getCryptokiInfo(unsigned long slot_id, CRYPTOKI_INFO *cryptoki_info)
{
    (void)slot_id;
    (void)cryptoki_info;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

int AvpassPrivate::getPinTriesRemain(NTCTW_PASS_TYPE pass_type, int *pin_tries_remain)
{
    if (pass_type == NTCTW_PASS_TYPE::PIN1) {
        *pin_tries_remain = user_pin_tries_remain_;
    } else {
        return NTCTW_ERRORS::INVALID_PARAMETERS;
    }
    return NTCTW_ERRORS::SUCCESS;
}

int AvpassPrivate::pbkdf2(const unsigned char *pass, const unsigned long pass_len, const unsigned char* salt, const unsigned long salt_len, 
                        const  unsigned long it_count, unsigned char* out, const unsigned long out_len)
{
    (void)pass;
    (void)pass_len;
    (void)salt;
    (void)salt_len;
    (void)it_count;
    (void)out;
    (void)out_len;
    return NTCTW_ERRORS::FUNCTION_NOT_IMPLEMENTED;
}

unsigned long AvpassPrivate::getNewHashCspHandle()
{
    unsigned long new_hash_csp_handle = static_cast<unsigned long>(session_->hash_csp_list.size() + 1);
    while (session_->hash_csp_list.count(new_hash_csp_handle) != 0) {
        ++new_hash_csp_handle;
    }
    return new_hash_csp_handle;
}

unsigned long AvpassPrivate::getNewKeyCspHandle()
{
    unsigned long new_key_handle = static_cast<unsigned long>(session_->key_csp_list.size() + 1);
    while (session_->key_csp_list.count(new_key_handle) != 0) {
        ++new_key_handle;
    }
    return new_key_handle;
}


Avpass::Avpass()
    : Avpass(*new AvpassPrivate())
{

}

Avpass::~Avpass()
{

}

Avpass::Avpass(AvpassPrivate &d)
    : d_ptr(&d)
{

}

int Avpass::loadFunctionList()
{
    return d_ptr->loadFunctionList();
}

int Avpass::initialize()
{
    return d_ptr->initialize();
}

int Avpass::finalize()
{
    return d_ptr->finalize();
}

int Avpass::getSlotList(std::vector<unsigned long> &slot_list)
{
    return d_ptr->getSlotList(slot_list);
}

int Avpass::getSlotNameById(unsigned long slot_id, std::vector<unsigned char> &slot_name)
{
    return d_ptr->getSlotNameById(slot_id, slot_name);
}

int Avpass::openSession(const unsigned long slot_id)
{
    return d_ptr->openSession(slot_id);
}

int Avpass::closeSession()
{
    return d_ptr->closeSession();
}

int Avpass::resetToken(unsigned long slot_id, const unsigned char* so_pin, unsigned long so_pin_size, const std::string& label)
{
    return d_ptr->resetToken(slot_id, so_pin, so_pin_size, label);
}

int Avpass::isAuthorized(const std::string &key_id)
{
    return d_ptr->isAuthorized(key_id);
}

int Avpass::login(const NTCTW_USER_TYPE user_type, unsigned char *pin, unsigned long pin_size)
{
    return d_ptr->login(user_type, pin, pin_size);
}

int Avpass::logout()
{
    return d_ptr->logout();
}

unsigned long Avpass::getHashContextSize()
{
    return d_ptr->getHashContextSize();
}

int Avpass::hashInit(void *hash_ctx, const NTCTW_HASH_ALG alg)
{
    return d_ptr->hashInit(hash_ctx, alg);
}

int Avpass::hashUpdate(void *hash_ctx, const unsigned char *data, const unsigned long size)
{
    return d_ptr->hashUpdate(hash_ctx, data, size);
}

int Avpass::hashFinal(void *hash_ctx, unsigned char *buf, const unsigned long buf_size)
{
    return d_ptr->hashFinal(hash_ctx, buf, buf_size);
}

int Avpass::hashControl(void *hash_ctx, int param_type, void *param, unsigned long param_len)
{
    return d_ptr->hashControl(hash_ctx, param_type, param, param_len);
}

int Avpass::hashCopy(void *hash_ctx_to, void *hash_ctx_from)
{
    return d_ptr->hashCopy(hash_ctx_to, hash_ctx_from);
}

int Avpass::hashCleanup(void *hash_ctx)
{
    return d_ptr->hashCleanup(hash_ctx);
}

int Avpass::enumKeys(bool is_private, std::vector<std::string> &keys)
{
    return d_ptr->enumKeys(is_private, keys);
}

int Avpass::loadKey(const std::string &id, bool is_private, unsigned long *key_handle, unsigned long *sec_level)
{
    return d_ptr->loadKey(id, is_private, key_handle, sec_level);
}

int Avpass::enumCertificates(std::vector<std::string> &certs)
{
    return d_ptr->enumCertificates(certs);
}

int Avpass::loadCertificate(const std::string &id, unsigned char *cert_val, unsigned long *cert_size)
{
    return d_ptr->loadCertificate(id, cert_val, cert_size);
}

int Avpass::sign(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
                 const unsigned char *tbs, const unsigned long tbs_len, unsigned char *out, size_t *out_len)
{
    return d_ptr->sign(key_handle, sec_level, hash_alg, need_to_calc_hash, tbs, tbs_len, out, out_len);
}

int Avpass::verify(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
                   const unsigned char *tbs, const unsigned long tbs_len, const unsigned char *sig, const unsigned long sig_len)
{
    return d_ptr->verify(key_handle, sec_level, hash_alg, need_to_calc_hash, tbs, tbs_len, sig, sig_len);
}

int Avpass::encrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header,
                    unsigned long header_len, unsigned char *out, size_t *out_len)
{
    return d_ptr->encrypt(key_handle, in, in_len, header, header_len, out, out_len);
}

int Avpass::decrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header,
                    unsigned long header_len, unsigned char *out, size_t *out_len)
{
    return d_ptr->decrypt(key_handle, in, in_len, header, header_len, out, out_len);
}

int Avpass::deriveKey(unsigned long priv_key_handle, unsigned long peer_pub_key_handle, unsigned char *derived_key,
                      unsigned long derived_key_len)
{
    return d_ptr->deriveKey(priv_key_handle, peer_pub_key_handle, derived_key, derived_key_len);
}

int Avpass::createPublicKey(const std::string &id, const std::string &label, const bool is_ephemeral,
                            const unsigned long sec_level, const unsigned char *value, const unsigned long size,
                            unsigned long *key_handle)
{
    return d_ptr->createPublicKey(id, label, is_ephemeral, sec_level, value, size, key_handle);
}

int Avpass::createPrivateKey(const std::string &id, const std::string &label, const bool is_ephemeral,
                             const unsigned long sec_level, const unsigned char *value, const unsigned long size,
                             unsigned long *key_handle)
{
    return d_ptr->createPrivateKey(id, label, is_ephemeral, sec_level, value, size, key_handle);
}

int Avpass::createCertificate(const std::string &id, const std::string &label, const bool is_ephemeral,
                              const unsigned char *value, const unsigned long size)
{
    return d_ptr->createCertificate(id, label, is_ephemeral, value, size);
}

int Avpass::comparePublicKeys(const unsigned long key_handle_one, const unsigned long key_handle_two, const unsigned long sec_level)
{
    return d_ptr->comparePublicKeys(key_handle_one, key_handle_two, sec_level);
}

int Avpass::generateKeyPair(const std::string &key_label, const unsigned long sec_level, const bool is_ephemeral,
                            unsigned long *pub_key_handle, unsigned long *priv_key_handle)
{
    return d_ptr->generateKeyPair(key_label, sec_level, is_ephemeral, pub_key_handle, priv_key_handle);
}

int Avpass::destroyKey(const unsigned long key_handle)
{
    return d_ptr->destroyKey(key_handle);
}

int Avpass::destroyCertificate(const std::string& id)
{
    return d_ptr->destroyCertificate(id);
}

int Avpass::getPublicKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size)
{
    return d_ptr->getPublicKeyValue(key_handle, buf, buf_size);
}

int Avpass::getPrivateKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size)
{
    return d_ptr->getPrivateKeyValue(key_handle, buf, buf_size);
}

int Avpass::cipherInit(void **cipher_ctx, NTCTW_CIPHER_ALG cipher_algid, const unsigned char *key,
                       const unsigned long key_len, const unsigned char *iv, const unsigned long iv_len, int enc_mode)
{
    return d_ptr->cipherInit(cipher_ctx, cipher_algid, key, key_len, iv, iv_len, enc_mode);
}

int Avpass::cipherControl(void *cipher_ctx, int param_type, void *param, unsigned long param_len)
{
    return d_ptr->cipherControl(cipher_ctx, param_type, param, param_len);
}

int Avpass::cipherDo(void *cipher_ctx, const unsigned char *in, unsigned long in_len, unsigned char *out)
{
    return d_ptr->cipherDo(cipher_ctx, in, in_len, out);
}

int Avpass::cipherCleanup(void *cipher_ctx)
{
    return d_ptr->cipherCleanup(cipher_ctx);
}

int Avpass::randAddEntropy(const unsigned char *buf, unsigned long size)
{
    return d_ptr->randAddEntropy(buf, size);
}

int Avpass::randBytes(unsigned char *buf, unsigned long size)
{
    return d_ptr->randBytes(buf, size);
}

void Avpass::randCleanup()
{
    return d_ptr->randCleanup();
}

int Avpass::changePin(CHANGE_PIN_PAYLOD *change_pin_payload)
{
    return d_ptr->changePin(change_pin_payload);
}

int Avpass::unblockPin(UNBLOCK_PIN_PAYLOAD *unblock_pin_payload)
{
    return d_ptr->unblockPin(unblock_pin_payload);
}

int Avpass::getCryptokiInfo(unsigned long slot_id, CRYPTOKI_INFO *cryptoki_info)
{
    return d_ptr->getCryptokiInfo(slot_id, cryptoki_info);
}

int Avpass::getPinTriesRemain(NTCTW_PASS_TYPE pass_type, int *pin_tries_remain)
{
    return d_ptr->getPinTriesRemain(pass_type, pin_tries_remain);
}

int Avpass::pbkdf2(const unsigned char *pass, const unsigned long pass_len, const unsigned char* salt, const unsigned long salt_len, 
                        const  unsigned long it_count, unsigned char* out, const unsigned long out_len)
{
    return d_ptr->pbkdf2(pass, pass_len, salt, salt_len, it_count, out, out_len);
}
