#include "config.h"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>

bool AppConfig::loadFromFile(const std::string& path) {
    try {
        YAML::Node root = YAML::LoadFile(path);

        if (root["server"] && root["server"]["port"])
            port = root["server"]["port"].as<int>(port);

        if (root["provider_name"])
            provider_name = root["provider_name"].as<std::string>();

        if (root["keys"] && root["keys"].IsSequence()) {
            keys.clear();
            for (const auto& k : root["keys"]) {
                KeyEntry e;
                if (k["key_id"])    e.key_id    = k["key_id"].as<std::string>();
                if (k["pin"])       e.pin       = k["pin"].as<std::string>();
                if (k["cert_path"]) e.cert_path = k["cert_path"].as<std::string>();
                keys.push_back(e);
            }
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

const KeyEntry* AppConfig::getKeyEntry(const std::string& keyId) const {
    for (const auto& e : keys) {
        if (e.key_id == keyId)
            return &e;
    }
    return nullptr;
}
