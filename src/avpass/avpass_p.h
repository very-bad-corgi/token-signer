#ifndef __AVPASS_P__H__
#define __AVPASS_P__H__

#include <ntctw_types.h>

#include <memory>
#include <vector>


class SoftToken;
struct AVPASS_SESSION;

class AvpassPrivate
{
public:
    AvpassPrivate();
    ~AvpassPrivate();

public:
    int loadFunctionList();
    int initialize();
    int finalize();
    int getSlotList(std::vector<unsigned long> &slot_list);
    int getSlotNameById(unsigned long slot_id, std::vector<unsigned char>& slot_name);
    int openSession(const unsigned long slot_id);
    int closeSession();
    int resetToken(unsigned long slot_id, const unsigned char* so_pin, unsigned long so_pin_size,
                              const std::string& label);

    int isAuthorized(const std::string &key_id);
    int login(const NTCTW_USER_TYPE user_type, unsigned char *pin, unsigned long pin_size);
    int logout();
    unsigned long getHashContextSize();
    int hashInit(void *hash_ctx, const NTCTW_HASH_ALG alg);
    int hashUpdate(void *hash_ctx, const unsigned char *data, const unsigned long size);
    int hashFinal(void *hash_ctx, unsigned char *buf, const unsigned long buf_size);
    int hashControl(void *hash_ctx, int param_type, void *param, unsigned long param_len);
    int hashCopy(void *hash_ctx_to, void *hash_ctx_from);
    int hashCleanup(void *hash_ctx);
    int enumKeys(bool is_private, std::vector<std::string> &keys);
    int loadKey(const std::string &id, bool is_private, unsigned long *key_handle, unsigned long *sec_level);
    int enumCertificates(std::vector<std::string> &certs);
    int loadCertificate(const std::string &id, unsigned char *cert_val, unsigned long *cert_size);
    int sign(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
             const unsigned char *tbs, const unsigned long tbs_len, unsigned char *out, size_t *out_len);
    int verify(unsigned long key_handle, unsigned long sec_level, NTCTW_HASH_ALG hash_alg, bool need_to_calc_hash,
               const unsigned char *tbs, const unsigned long tbs_len, const unsigned char *sig, const unsigned long sig_len);
    int encrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header, unsigned long header_len,
                unsigned char *out, size_t *out_len);
    int decrypt(unsigned long key_handle, const unsigned char *in, size_t in_len, const unsigned char *header, unsigned long header_len,
                unsigned char *out, size_t *out_len);
    int deriveKey(unsigned long priv_key_handle, unsigned long peer_pub_key_handle, unsigned char *derived_key, unsigned long derived_key_len);
    int createPublicKey(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level,
                        const unsigned char *value, const unsigned long size, unsigned long *key_handle);
    int createPrivateKey(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned long sec_level,
                         const unsigned char *value, const unsigned long size, unsigned long *key_handle);
    int createCertificate(const std::string &id, const std::string &label, const bool is_ephemeral, const unsigned char *value,
                          const unsigned long size);
    int comparePublicKeys(const unsigned long key_handle_one, const unsigned long key_handle_two, const unsigned long sec_level);
    int generateKeyPair(const std::string &key_label, const unsigned long sec_level, const bool is_ephemeral, unsigned long *pub_key_handle, unsigned long *priv_key_handle);
    int destroyKey(const unsigned long key_handle);
    int destroyCertificate(const std::string& id);
    int getPublicKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size);
    int getPrivateKeyValue(const unsigned long key_handle, unsigned char *buf, const unsigned long buf_size);
    int cipherInit(void **cipher_ctx, NTCTW_CIPHER_ALG cipher_algid, const unsigned char *key, const unsigned long key_len, const unsigned char *iv, const unsigned long iv_len, int enc_mode);
    int cipherControl(void *cipher_ctx, int param_type, void *param, unsigned long param_len);
    int cipherDo(void *cipher_ctx, const unsigned char *in, unsigned long in_len, unsigned char *out);
    int cipherCleanup(void *cipher_ctx);
    int randAddEntropy(const unsigned char *buf, unsigned long size);
    int randBytes(unsigned char *buf, unsigned long size);
    void randCleanup();

    int changePin(CHANGE_PIN_PAYLOD* change_pin_payload);
    int unblockPin(UNBLOCK_PIN_PAYLOAD* unblock_pin_payload);
    int getCryptokiInfo(unsigned long slot_id, CRYPTOKI_INFO* cryptoki_info);
    int getPinTriesRemain(NTCTW_PASS_TYPE pass_type, int* pin_tries_remain);
    int pbkdf2(const unsigned char *pass, const unsigned long pass_len, const unsigned char* salt, const unsigned long salt_len, 
                        const  unsigned long it_count, unsigned char* out, const unsigned long out_len);

private:
    unsigned long getNewKeyCspHandle();
    unsigned long getNewHashCspHandle();

private:
    std::unique_ptr<SoftToken> soft_token_;
    std::unique_ptr<AVPASS_SESSION> session_;
    int user_pin_tries_remain_ = 3;
    std::vector<std::vector<unsigned char>> devices_;
};

#endif // __AVPASS_P__H__
