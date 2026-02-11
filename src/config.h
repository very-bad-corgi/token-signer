#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>

struct KeyEntry {
    std::string key_id;
    std::string pin;
    std::string cert_path;  // путь к сертификату, соответствующему этому ключу
};

struct AppConfig {
    int port = 8080;
    std::string provider_name = "Avest CSP Bel Pro";
    std::vector<KeyEntry> keys;

    // Логирование: файл, ротация по числу строк, кол-во хранимых файлов
    std::string log_file = "logs/service.log";
    int log_max_lines = 10000;
    int log_max_files = 3;

    /** Загружает конфиг из YAML-файла. Возвращает true при успехе. */
    bool loadFromFile(const std::string& path);

    /** Возвращает запись ключа по key_id или nullptr, если не найден. */
    const KeyEntry* getKeyEntry(const std::string& keyId) const;
};

#endif // CONFIG_H
