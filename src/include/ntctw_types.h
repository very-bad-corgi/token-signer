#ifndef __NTCTW__ERRORS__H__
#define __NTCTW__ERRORS__H__

enum NTCTW_ERRORS
{
    SUCCESS = 0,
    UNKNOWN_ERROR,
    NO_MEMORY,
    BROKEN_RNG,
    UNSUPPORTED_CRYPTOKI,
    FAILED_TO_LOAD_LIBRARY,
    FAILED_TO_RESOLVE_SYMBOLS,
    CRYPTOKI_NOT_INITIALIZED,
    SESSION_HANDLE_INVALID,
    SESSION_ALREADY_OPEN,
    UNSUPPORTED_ALGORITHM,
    INVALID_PARAMETERS,
    UNKNOWN_USER_TYPE,
    USER_NOT_LOGGED_IN,
    KEY_NOT_FOUND,
    FAILED_TO_GET_OBJECT_ATTRIBUTE,
    SIGN_OPERATION_NOT_INITIALIZED,
    SIGN_OPEARION_FAILED,
    VERIFY_OPERATION_NOT_INITIALIZED,
    VERIFY_OPERATION_FAILED,
    SIGNATURE_INVALID,
    ERROR_BUFFER_TO_SMALL,
    FAILED_TO_CREATE_OBJECT,
    KEYS_NOT_EQUAL,
    FAILED_TO_GENERATE_KEY_PAIR,
    FUNCTION_NOT_IMPLEMENTED,
    FAILED_TO_READ_FILE,
    KEY_FILE_INVALID,
    NO_PRIVATE_KEY,
    PUBLIC_KEY_GENERATION_FAILED,
    KEY_ALREADY_EXISTS,
    OPERATION_FAILED,
    CONFIG_NOT_FOUND,
    CRYPTOKI_NOT_FOUND,
    FILE_NOT_FOUND,
    PASSWORD_INVALID
};

enum NTCTW_HASH_ALG
{
    BELT_HASH256,
    BASH256,
    BASH384,
    BASH512,
    BELT_MAC128,
    BELT_MAC192,
    BELT_MAC256
};

// Удобный алиас для использования в коде
constexpr NTCTW_HASH_ALG NTCTW_BELT_HASH_ALG = BELT_HASH256;

enum NTCTW_CIPHER_ALG
{
    UNDEFINED_CIPHER = -1,
    BELT_ECB,
    BELT_CBC,
    BELT_CFB,
    BELT_CTR,
    BELT_KWR,
    BELT_DWR
};

enum NTCTW_USER_TYPE
{
    user,
    administrator,
    security_admin
};

enum NTCTW_CRYPTOKI_TYPES
{
    undefined = -1,
    sigma,
    sigma_tls,
    soft_token,
    bpki_cryptoki,
    id_card,
    ntstore,
    avbign,
    avbign_tls,
    avhsm,
    ntsks,
    sigma2,
    nthsm,
    avpass,
    old_sigma
};

enum ENGINE_TYPE
{
    hardware,
    software
};

enum NTCTW_CTRL
{
    CIPHER_CTRL_SET_IV,
    CIPHER_CTRL_SET_KEY,
    CIPHER_CTRL_SET_AAD,
    CIPHER_CTRL_GET_TAG,
    HASH_CTRL_SET_KEY,
    CIPHER_CTRL_SET_TAG,
    CIPHER_CTRL_RAND_KEY,
    CIPHER_CTRL_USE_PERSISTENT_KEY
};

enum STB31_TEST_NUM
{
    stb31_bs13, /* belt-ecb encrypt */
    stb31_bs14, /* belt-ecb encrypt */
    stb31_bs15, /* belt-ecb decrypt */
    stb31_bs16, /* belt-ecb decrypt */
    stb31_bs19, /* belt-cbc encrypt */
    stb31_bs20, /* belt-cbc encrypt */
    stb31_bs21, /* belt-cbc decrypt */
    stb31_bs22, /* belt-cbc decrypt */
    stb31_bs25, /* belt-cfb encrypt */
    stb31_bs26, /* belt-cfb decrypt */
    stb31_bs29, /* belt-ctr encrypt */
    stb31_bs31, /* belt-mac */
    stb31_bs32, /* belt-mac */
    stb31_bs35, /* belt-datawrap encrypt */
    stb31_bs36, /* belt-datawrap decrypt */
    stb31_bs39, /* belt-keywrap encrypt */
    stb31_bs40, /* belt-keywrap decrypt */
    stb31_bs42, /* belt-hash256 */
    stb31_bs43, /* belt-hash256 */
    stb31_bs44, /* belt-hash256 */
    stb31_bs46, /* belt-keyexpansion */
    stb31_bs47, /* belt-keyexpansion */
    stb31_bs49, /* belt-keyrep */
    stb31_bs50, /* belt-keyrep */
    stb31_bs51 /* belt-keyrep */
};

enum STB45_TEST_NUM
{
    stb45_bs7, /* generate public key */
    stb45_bs8, /* public key verify */
    stb45_bs10, /* generate k */
    stb45_bs11, /* make signature */
    stb45_bs12, /* verify signature */
    stb45_bs13, /* encrypt (key transport) */
    stb45_bs14, /* decrypt (key transport) */
    stb45_bs18, /* PBKDF2 */
    stb45_192_bs7, /* generate public key */
    stb45_192_bs8, /* public key verify */
    stb45_192_bs10, /* generate k */
    stb45_192_bs11, /* make signature */
    stb45_192_bs12, /* verify signature */
    stb45_192_bs13, /* encrypt (key transport) */
    stb45_192_bs14, /* decrypt (key transport) */
    stb45_256_bs7, /* generate public key */
    stb45_256_bs8, /* public key verify */
    stb45_256_bs10, /* generate k */
    stb45_256_bs11, /* make signature */
    stb45_256_bs12, /* verify signature */
    stb45_256_bs13, /* encrypt (key transport) */
    stb45_256_bs14 /* decrypt (key transport) */
};

enum STB47_TEST_NUM
{
    stb47_bs1, /* hmac-hbelt */
    stb47_bs2, /* hmac-hbelt */
    stb47_bs3, /* hmac-hbelt */
    stb47_bs5, /* brng-hmac-hbelt */
    stb47_bs7, /* brng-ctr-hbelt */
    stb47_bs14, /* totp-hbelt */
    stb47_bs15, /* totp-hbelt */
    stb47_bs16, /* totp-hbelt */
};

enum STB77_TEST_NUM
{
    stb77_1, /* bash256 */
    stb77_2, /* bash256 */
    stb77_3, /* bash256 */
    stb77_4, /* bash256 */
    stb77_5, /* bash384 */
    stb77_6, /* bash384 */
    stb77_7, /* bash384 */
    stb77_8, /* bash512 */
    stb77_9, /* bash512 */
    stb77_10, /* bash512 */
    stb77_11, /* bash512 */
};

enum STB60_TEST_NUM
{
    stb60_2, /* share, l= 128 */
    stb60_3, /* share, l = 192 */
    stb60_4, /* share, l = 256 */
    stb60_5, /* recover, l = 128 */
    stb60_6, /* recover, l = 192 */
    stb60_7  /* recover, l = 256 */
};

enum STB66_TEST_NUM
{
    stb66_bpace_side_a_test,
    stb66_bpace_side_b_test,
    stb66_bs4
};

enum BAUTH_STEP
{
    init_step, /* инициализация протокола */
    check_cert, /* проверка сертификата терминала */
    send_m0, /* отправка сообщения М0 */
    send_m1, /* отправка сообщения М1 */
    send_m2, /* отправка сообщения М2 */
    send_m3 /* отправка сообщения М3 */
};

enum NTCTW_PASS_TYPE
{
    PIN1,
    PIN2,
    PUK
};

typedef struct SHARE_SECRET_PASS_ST {
    unsigned char *pass;
    unsigned long pass_len;
} SHARE_SECRET_PASS;

typedef struct SECRET_SHARD_ST {
    unsigned char* buf;
    unsigned long buf_size;
} SECRET_SHARD, DATA_BUFFER;

typedef struct STB_TESTS_ID_LISTS_ST {
    /*
     * список id тестов СТБ 34.101.31, которые необходимо выполнить
     * id теста = соответствующее значение из STB31_TEST_NUM
     */
    int* stb31_test_id_list;
    unsigned long stb31_test_id_list_size;
    /*
     * список id тестов СТБ 34.101.45, которые необходимо выполнить
     * id теста = соответствующее значение из STB45_TEST_NUM
     */
    int* stb45_test_id_list;
    unsigned long stb45_test_id_list_size;
    /*
     * список id тестов СТБ 34.101.47, которые необходимо выполнить
     * id теста = соответствующее значение из STB47_TEST_NUM
     */
    int* stb47_test_id_list;
    unsigned long stb47_test_id_list_size;
    /*
     * список id тестов СТБ 34.101.77, которые необходимо выполнить
     * id теста = соответствующее значение из STB77_TEST_NUM
     */
    int* stb77_test_id_list;
    unsigned long stb77_test_id_list_size;
    int* stb60_test_id_list;
    unsigned long stb60_test_id_list_size;
    /*
     * список id тестов СТБ 34.101.66, которые необходимо выполнить
     * id теста = соответствующее значение из STB66_TEST_NUM
     */
    int* stb66_test_id_list;
    unsigned long stb66_test_id_list_size;
} STB_TESTS_ID_LISTS;

typedef struct KEY_LIST_ST {
    /* какого типа получать ключи (личные\открытые) */
    int is_private;
    /* список id ключей на носителе */
    char** key_ids;
    /* количество ключей */
    unsigned long num;
} KEY_LIST;

typedef struct CERT_LIST_ST {
    /* список id сертификатов на носителе */
    char** cert_ids;
    /* количество сертификатов */
    unsigned long num;
} CERT_LIST;

typedef struct BAUTH_PAYLOAD_ST {
    /* текущий шаг протокола (см. описание типа BAUTH_STEP) */
    enum BAUTH_STEP current_step;
    struct {
        /* тип BAUTH (с взаимной авторизацией или без) */
        int is_bilateral;
        /* указатель на буфер, содержащий cdf часть APDU команды */
        const unsigned char* cmd;
        /* размер этого буфера */
        unsigned long cmd_len;
    } init;
    struct {
        /* указатель на буфер, содержащий значение сертификата */
        const unsigned char* cert;
        /* размер этого буфера */
        unsigned long cert_len;
    } check_cert;
    struct {
        /* указатель на буфер, содержащий cdf часть APDU команды */
        const unsigned char* cmd;
        /* размер этого буфера */
        unsigned long cmd_len;
        /* указатель на буфер, получающий ответ */
        unsigned char* answer;
        /* размер буфера */
        unsigned long answer_len;
    } step;
} BAUTH_PAYLOAD;

typedef struct KTA_FILE_ST {
    /* id файла */
    unsigned short FID;
    /* буфер, куда будут скопированы данные файла */
    unsigned char* content;
    /* размер этого файла */
    unsigned long content_size;
} KTA_FILE;

typedef struct TERMINAL_PAYLOAD_ST {
    unsigned char cla;
    unsigned char ins;
    unsigned char p1;
    unsigned char p2;
    const unsigned char* cdf;
    unsigned long cdf_size;
    unsigned char* rdf;
    unsigned long rdf_size;
} TERMINAL_PAYLOAD;

typedef struct CHANGE_PIN_PAYLOAD_ST {
    /*
     * тип PIN кода
     * для КТА:
     *  1 - PIN1
     *  2 - PIN2
     * для cryptoki:
     *  1 - CKU_USER
     *  2 - CKU_SO
     */
    unsigned int type;
    /* старый PIN код */
    unsigned char* old_pin;
    unsigned long old_pin_size;
    /* новый PIN код */
    unsigned char* new_pin;
    unsigned long new_pin_size;
} CHANGE_PIN_PAYLOD;

typedef struct UNBLOCK_PIN_PAYLOAD_ST {
    struct {
        /*
         * тип PIN кода
         * для КТА:
         *  1 - PIN1
         *  2 - PIN2
         */
        unsigned int type;
        /* нужно ли изменять PIN  - код */
        int need_to_change_pin;
        /* если да - новое значение PIN - кода */
        unsigned char* new_pin;
        unsigned long new_pin_size;
    } kta;
    struct {
        unsigned char* puk;
        unsigned long puk_size;
    } cryptoki;
} UNBLOCK_PIN_PAYLOAD;

typedef struct SLOT_ID_LIST_ST {
    unsigned long* slot_id;
    unsigned long count;
} SLOT_ID_LIST;

typedef struct SLOT_NAME_ST {
    unsigned long id;
    unsigned char* name;
    unsigned long size;
} SLOT_NAME;

typedef struct SLOT_SERIAL_NUMBERS_ST {
    unsigned long slot_id;
    unsigned char* sn;
    unsigned long sn_size;
} SLOT_SERIAL_NUMBERS;

typedef struct CREATE_KEY_PAIR_PAYLOAD_ST {
    const char* id;
    int is_ephemeral;
    const char* label;
    unsigned long security_level;
    const unsigned char* pub_value;
    unsigned long pub_value_size;
    const unsigned char* priv_value;
    unsigned long priv_value_size;
    /* EVP_PKEY* type */
    void* pkey;
} CREATE_KEY_PAIR_PAYLOAD;

#ifdef NTHSM_SUPPORT

typedef struct NTHSM_CREATE_SLOT_PAYLOAD_ST {
    struct {
        unsigned char label[14];
        int token_type;
        int token_owner;
        unsigned char nki_id[16];
        unsigned char part_pin[32];
    } slot_info;
    const unsigned char* pin;
    unsigned long pin_size;
    /* выходной параметр */
    unsigned long slot_id;
} NTHSM_CREATE_SLOT_PAYLOAD;

typedef struct NTHSM_SLOT_ID_LIST_ST {
    unsigned long hsm_num;
    unsigned long* slot_id;
    unsigned long count;
} NTHSM_SLOT_ID_LIST;

typedef struct NTHSM_VERSION_ST {
    unsigned char       major;  /* integer portion of version number */
    unsigned char       minor;  /* 1/100ths portion of version number */
} NTHSM_VERSION;

typedef struct NTHSM_SLOT_INFO_ST {
    /* slotDescription and manufacturerID have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
    unsigned char   slotDescription[64];  /* blank padded */
    unsigned char   manufacturerID[32];   /* blank padded */
    unsigned long int      flags;

    NTHSM_VERSION    hardwareVersion;  /* version of hardware */
    NTHSM_VERSION    firmwareVersion;  /* version of firmware */
} NTHSM_SLOT_INFO;

typedef struct NTHSM_GET_SLOT_INFO_PAYLOAD_ST {
    unsigned long slot_id;
    NTHSM_SLOT_INFO* slot_info;
} NTHSM_GET_SLOT_INFO_PAYLOAD;

/* CK_TOKEN_INFO provides information about a token */
typedef struct NTHSM_TOKEN_INFO_ST {
    /* label, manufacturerID, and model have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
    unsigned char   label[32];           /* blank padded */
    unsigned char   manufacturerID[32];  /* blank padded */
    unsigned char   model[16];           /* blank padded */
    unsigned char   serialNumber[16];    /* blank padded */
    unsigned long int      flags;               /* see below */
    unsigned long int      ulMaxSessionCount;     /* max open sessions */
    unsigned long int      ulSessionCount;        /* sess. now open */
    unsigned long int      ulMaxRwSessionCount;   /* max R/W sessions */
    unsigned long int      ulRwSessionCount;      /* R/W sess. now open */
    unsigned long int      ulMaxPinLen;           /* in bytes */
    unsigned long int      ulMinPinLen;           /* in bytes */
    unsigned long int      ulTotalPublicMemory;   /* in bytes */
    unsigned long int      ulFreePublicMemory;    /* in bytes */
    unsigned long int      ulTotalPrivateMemory;  /* in bytes */
    unsigned long int      ulFreePrivateMemory;   /* in bytes */
    NTHSM_VERSION    hardwareVersion;       /* version of hardware */
    NTHSM_VERSION    firmwareVersion;       /* version of firmware */
    unsigned char       utcTime[16];           /* time */
} NTHSM_TOKEN_INFO;


typedef struct NTHSM_TOKEN_INFO_PAYLOAD_ST {
    unsigned long slot_id;
    NTHSM_TOKEN_INFO* token_info;
} NTHSM_TOKEN_INFO_PAYLOAD;

#endif

typedef struct CRYPTOKI_INFO_ST {
    int pin_tries_remain;
} CRYPTOKI_INFO ;

typedef struct CRYPTOKI_INFO_PAYLOAD_ST {
    unsigned long slot_id;
    CRYPTOKI_INFO* cryptoki_info;
} CRYPTOKI_INFO_PAYLOAD;

typedef struct GET_PIN_TRIES_PAYLOAD_ST {
    enum NTCTW_PASS_TYPE pass_type;
    int pin_tries_remain;
} GET_PIN_TRIES_PAYLOAD;

#endif // __NTCTW__ERRORS__H__

