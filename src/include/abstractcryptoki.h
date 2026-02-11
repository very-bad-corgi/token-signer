#ifndef __ABSTRACT__CRYPTOKI__H__
#define __ABSTRACT__CRYPTOKI__H__

#include <ntctw_types.h>

#include <vector>
#include <string>

class AbstractCryptoki
{
public:
    AbstractCryptoki() {}
    virtual ~AbstractCryptoki() = default;

public:
    virtual int loadFunctionList() = 0;
    virtual int initialize() = 0;
    virtual int finalize() = 0;
    virtual int getSlotList(std::vector<unsigned long int>& slot_list) = 0;
    virtual int getSlotNameById(unsigned long slot_id, std::vector<unsigned char>& slot_name) = 0;
    virtual int openSession(const unsigned long int slot_id) = 0;
    virtual int closeSession() = 0;
    virtual int resetToken(unsigned long slot_id, const unsigned char* so_pin, unsigned long so_pin_size,
                          const std::string& label) = 0;

    virtual int isAuthorized(const std::string& key_id) = 0;
    virtual int login(const NTCTW_USER_TYPE user_type, unsigned char* pin, unsigned long pin_size) = 0;
    virtual int logout() = 0;

    virtual unsigned long getHashContextSize() = 0;
    virtual int hashInit(void* hash_ctx, const NTCTW_HASH_ALG alg) = 0;
    virtual int hashUpdate(void* hash_ctx, const unsigned char* data, const unsigned long size) = 0;
    virtual int hashFinal(void* hash_ctx, unsigned char* buf, const unsigned long buf_size) = 0;
    virtual int hashControl(void* hash_ctx, int param_type, void *param, unsigned long param_len) = 0;
    virtual int hashCopy(void* hash_ctx_to, void* hash_ctx_from) = 0;
    virtual int hashCleanup(void* hash_ctx) = 0;

    virtual int enumKeys(bool is_private, std::vector<std::string>& keys) = 0;
    virtual int loadKey(const std::string& id, bool is_private, unsigned long* key_handle, unsigned long* sec_level) = 0;
    virtual int enumCertificates(std::vector<std::string>& certs) = 0;
    virtual int loadCertificate(const std::string& id, unsigned char* cert_val, unsigned long* cert_size) = 0;

    /**
     * @brief signInit - инициализация операции подписи
     * @param key_handle - хэндл приватного ключа
     * @param sec_level - уровень стойкости ключа
     * @param hash_alg - алгоритм хэширования
     * @param need_to_calc_hash:
     *        - true - на вход функции подписи будут подаваться данные, тогда
     *          цепочка вызовов: signInit -> signUpdate (n раз) -> signFinal
     *        - false - на вход функции подписи подаётся ХЭШ - значение,
     *          цепочка вызовов: signInit -> sign
     * @return
     */
    /**
     * @brief sign - подпись сформированного ХЭШ - значения. Должна вызываться, если
     *              в функции signInit было указано need_to_calc_hash = false
     * @param tbs - буфер, содержащий хэш - значение
     * @param tbs_len - размер буфера tbs
     * @param out - буфер, куда будет записано значение подписи. Если равно nullptr, значит
     *              функция вызвана для получения размера буфера, который будет возвращен в *out_len*
     * @param out_len - размер буфера out
     * @return
     */
    virtual int sign(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
                     const unsigned char* tbs, const unsigned long tbs_len, unsigned char* out, size_t* out_len) = 0;

    virtual int verify(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
                       const unsigned char* tbs, const unsigned long tbs_len, const unsigned char* sig, const unsigned long sig_len) = 0;

    virtual int encrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header,
                        unsigned long header_len, unsigned char *out, size_t *out_len) = 0;
    virtual int decrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header,
                        unsigned long header_len, unsigned char *out, size_t *out_len) = 0;
    virtual int deriveKey(unsigned long priv_key_handle, unsigned long peer_pub_key_handle,
                          unsigned char* derived_key, unsigned long derived_key_len) = 0;

    virtual int createPublicKey(const std::string& id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level,
                                const unsigned char* value, const unsigned long size, unsigned long *key_handle) = 0;
    virtual int createPrivateKey(const std::string& id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level,
                                 const unsigned char* value, const unsigned long size, unsigned long *key_handle) = 0;
    virtual int createCertificate(const std::string& id, const std::string &label, const bool is_ephemeral, const unsigned char* value,
                                  const unsigned long size) = 0;

    virtual int comparePublicKeys(const unsigned long key_handle_one, const unsigned long key_handle_two, const unsigned long sec_level) = 0;

    virtual int generateKeyPair(const std::string& key_label, const unsigned long sec_level, const bool is_ephemeral,
                                unsigned long* pub_key_handle, unsigned long* priv_key_handle) = 0;
    virtual int destroyKey(const unsigned long key_handle) = 0;
    virtual int destroyCertificate(const std::string& id) = 0;

    virtual int getPublicKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size) = 0;
    virtual int getPrivateKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size) = 0;

    virtual int cipherInit(void** cipher_ctx, enum  NTCTW_CIPHER_ALG cipher_algid, const unsigned char *key, const unsigned long key_len,
                           const unsigned char *iv, const unsigned long iv_len, int enc_mode) = 0;
    virtual int cipherControl(void* cipher_ctx, int param_type, void* param, unsigned long param_len) = 0;
    /* функция возвращает размер зашифрованных данных, либо -1 в случае ошибки */
    virtual int cipherDo(void* cipher_ctx, const unsigned char* in, unsigned long in_len, unsigned char* out) = 0;
    virtual int cipherCleanup(void* cipher_ctx) = 0;

    virtual int randAddEntropy(const unsigned char* buf, unsigned long size) = 0;
    virtual int randBytes(unsigned char* buf, unsigned long size) = 0;
    virtual void randCleanup() = 0;

    virtual int changePin(CHANGE_PIN_PAYLOD* change_pin_payload) = 0;
    virtual int unblockPin(UNBLOCK_PIN_PAYLOAD* unblock_pin_payload) = 0;
    virtual int getCryptokiInfo(unsigned long slot_id, CRYPTOKI_INFO* cryptoki_info) = 0;
    virtual int getPinTriesRemain(NTCTW_PASS_TYPE pass_type, int* pin_tries_remain) = 0;
    virtual int pbkdf2(const unsigned char *pass, const unsigned long pass_len, const unsigned char* salt, const unsigned long salt_len, 
                        const  unsigned long it_count, unsigned char* out, const unsigned long out_len) = 0;
};


#endif // __ABSTRACT__CRYPTOKI__H__
