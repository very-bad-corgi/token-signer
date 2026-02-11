#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>

struct KeyEntry {
    std::string key_id;
    std::string pin;
};

struct AppConfig {
    int port = 8080;
    std::string cert_path;
    std::string provider_name = "Avest CSP Bel Pro";
    std::vector<KeyEntry> keys;

    /** Загружает конфиг из YAML-файла. Возвращает true при успехе. */
    bool loadFromFile(const std::string& path);

    /** Возвращает pin для key_id или пустую строку. */
    std::string getPinForKey(const std::string& keyId) const;
};

#endif // CONFIG_H
