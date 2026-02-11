#ifndef __AVPASS__P__H__
#define __AVPASS__P__H__

#include "abstractcryptoki.h"

#include <memory>

class AvpassPrivate;

class Avpass final : public AbstractCryptoki
{
public:
    Avpass();
    ~Avpass() override;

    Avpass(const Avpass& other) = delete;
    void operator=(const Avpass& other) = delete;

protected:
    Avpass(AvpassPrivate& d);

    // AbstractCryptoki interface
public:
    int loadFunctionList() override;
    int initialize() override;
    int finalize() override;
    int getSlotList(std::vector<unsigned long> &slot_list) override;
    int getSlotNameById(unsigned long slot_id, std::vector<unsigned char>& slot_name) override;
    int openSession(const unsigned long slot_id) override;
    int closeSession() override;
    int resetToken(unsigned long slot_id, const unsigned char* so_pin, unsigned long so_pin_size,
                              const std::string& label) override;

    int isAuthorized(const std::string &key_id) override;
    int login(const NTCTW_USER_TYPE user_type, unsigned char *pin, unsigned long pin_size) override;
    int logout() override;
    unsigned long getHashContextSize() override;
    int hashInit(void *hash_ctx, const NTCTW_HASH_ALG alg) override;
    int hashUpdate(void *hash_ctx, const unsigned char *data, const unsigned long size) override;
    int hashFinal(void *hash_ctx, unsigned char *buf, const unsigned long buf_size) override;
    int hashControl(void *hash_ctx, int param_type, void *param, unsigned long param_len) override;
    int hashCopy(void *hash_ctx_to, void *hash_ctx_from) override;
    int hashCleanup(void *hash_ctx) override;
    int enumKeys(bool is_private, std::vector<std::string> &keys) override;
    int loadKey(const std::string &id, bool is_private, unsigned long *key_handle, unsigned long *sec_level) override;
    int enumCertificates(std::vector<std::string> &certs) override;
    int loadCertificate(const std::string &id, unsigned char *cert_val, unsigned long *cert_size) override;
    int sign(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
             const unsigned char *tbs, const unsigned long tbs_len, unsigned char *out, size_t *out_len) override;
    int verify(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
               const unsigned char *tbs, const unsigned long tbs_len, const unsigned char *sig, const unsigned long sig_len) override;
    int encrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header, unsigned long header_len,
                unsigned char *out, size_t *out_len) override;
    int decrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header, unsigned long header_len,
                unsigned char *out, size_t *out_len) override;
    int deriveKey(unsigned long priv_key_handle, unsigned long peer_pub_key_handle, unsigned char *derived_key, unsigned long derived_key_len) override;
    int createPublicKey(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level, const unsigned char *value, const unsigned long size, unsigned long *key_handle) override;
    int createPrivateKey(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level, const unsigned char *value, const unsigned long size, unsigned long *key_handle) override;
    int createCertificate(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned char *value,
                          const unsigned long size) override;
    int comparePublicKeys(const unsigned long key_handle_one, const unsigned long key_handle_two, const unsigned long sec_level) override;
    int generateKeyPair(const std::string &key_label, const unsigned long sec_level, const bool is_ephemeral, unsigned long *pub_key_handle, unsigned long *priv_key_handle) override;
    int destroyKey(const unsigned long key_handle) override;
    int destroyCertificate(const std::string& id) override;
    int getPublicKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size) override;
    int getPrivateKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size) override;
    int cipherInit(void **cipher_ctx, NTCTW_CIPHER_ALG cipher_algid, const unsigned char *key, const unsigned long key_len, const unsigned char *iv, const unsigned long iv_len, int enc_mode) override;
    int cipherControl(void *cipher_ctx, int param_type, void *param, unsigned long param_len) override;
    int cipherDo(void *cipher_ctx, const unsigned char *in, unsigned long in_len, unsigned char *out) override;
    int cipherCleanup(void *cipher_ctx) override;
    int randAddEntropy(const unsigned char *buf, unsigned long size) override;
    int randBytes(unsigned char *buf, unsigned long size) override;
    void randCleanup() override;

    int changePin(CHANGE_PIN_PAYLOD* change_pin_payload) override;
    int unblockPin(UNBLOCK_PIN_PAYLOAD* unblock_pin_payload) override;
    int getCryptokiInfo(unsigned long slot_id, CRYPTOKI_INFO* cryptoki_info) override;
    int getPinTriesRemain(NTCTW_PASS_TYPE pass_type, int* pin_tries_remain) override;
    int pbkdf2(const unsigned char *pass, const unsigned long pass_len, const unsigned char* salt, const unsigned long salt_len, 
                        const  unsigned long it_count, unsigned char* out, const unsigned long out_len) override;

private:
    friend class AvpassPrivate;

private:
    std::unique_ptr<AvpassPrivate> d_ptr;
};

#endif // __AVPASS__P__H__
