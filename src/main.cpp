#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <avpass.h>
#include <ntctw_types.h>
#include <cryptooperations.h>
#include <config.h>
#include <string>    // required by tkislan/base64.h
#include <base64.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>

using json = nlohmann::json;

static std::string findConfigPath() {
    std::ifstream f("config.yaml");
    if (f) return "config.yaml";
    wchar_t exePath[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) return "config.yaml";
    std::wstring wdir(exePath);
    size_t last = wdir.find_last_of(L"\\/");
    if (last != std::wstring::npos) wdir.resize(last);
    std::wstring candidate = wdir + L"\\config.yaml";
    if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
        int n = WideCharToMultiByte(CP_UTF8, 0, candidate.c_str(), -1, NULL, 0, NULL, NULL);
        if (n <= 0) return "config.yaml";
        std::string out(n - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, candidate.c_str(), -1, &out[0], n, NULL, NULL);
        return out;
    }
    return "config.yaml";
}

static std::string resolveCertPath(const std::string& configuredPath) {
    std::ifstream f(configuredPath);
    if (f) return configuredPath;
    wchar_t exePath[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) return configuredPath;
    std::wstring wdir(exePath);
    size_t last = wdir.find_last_of(L"\\/");
    if (last != std::wstring::npos) wdir.resize(last);
    int nw = MultiByteToWideChar(CP_UTF8, 0, configuredPath.c_str(), -1, NULL, 0);
    if (nw <= 0) return configuredPath;
    std::vector<wchar_t> wpath(nw);
    MultiByteToWideChar(CP_UTF8, 0, configuredPath.c_str(), -1, wpath.data(), nw);
    std::wstring candidate = wdir + L"\\" + wpath.data();
    if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
        int n = WideCharToMultiByte(CP_UTF8, 0, candidate.c_str(), -1, NULL, 0, NULL, NULL);
        if (n <= 0) return configuredPath;
        std::string out(n - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, candidate.c_str(), -1, &out[0], n, NULL, NULL);
        return out;
    }
    return configuredPath;
}

int main() {
    AppConfig config;
    std::string configPath = findConfigPath();
    if (!config.loadFromFile(configPath)) {
        std::cerr << "Failed to load config from " << configPath << std::endl;
        return 1;
    }
    std::cout << "Config loaded: port=" << config.port
              << ", keys=" << config.keys.size() << std::endl;

    httplib::Server svr;

    svr.Post("/cms", [&config](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "application/json; charset=utf-8");

        json body;
        try {
            body = json::parse(req.body);
        } catch (const json::exception&) {
            res.status = 400;
            res.set_content(json{{"error", "Invalid JSON"}}.dump(), "application/json");
            return;
        }

        std::string keyId = body.value("key_id", "");
        if (keyId.empty()) {
            res.status = 400;
            res.set_content(json{{"error", "Missing key_id"}}.dump(), "application/json");
            return;
        }

        const KeyEntry* key = config.getKeyEntry(keyId);
        if (!key || key->cert_path.empty()) {
            res.status = 400;
            res.set_content(json{{"error", "Unknown key_id or key has no cert_path in config"}}.dump(), "application/json");
            return;
        }

        std::string certPath = resolveCertPath(key->cert_path);

        std::vector<unsigned char> dataToSign;
        if (body.contains("data_b64")) {
            std::string b64 = body["data_b64"].get<std::string>();
            std::string decoded;
            if (!Base64::Decode(b64, &decoded)) {
                res.status = 400;
                res.set_content(json{{"error", "Invalid data_b64"}}.dump(), "application/json");
                return;
            }
            dataToSign.assign(decoded.begin(), decoded.end());
        } else if (body.contains("data")) {
            std::string dataStr = body["data"].get<std::string>();
            dataToSign.assign(dataStr.begin(), dataStr.end());
        } else {
            res.status = 400;
            res.set_content(json{{"error", "Missing data or data_b64 in body"}}.dump(), "application/json");
            return;
        }

        if (dataToSign.empty()) {
            res.status = 400;
            res.set_content(json{{"error", "Data to sign is empty"}}.dump(), "application/json");
            return;
        }

        std::vector<unsigned char> cmsVec = CryptoOperations::generateCMS(
            dataToSign,
            config.provider_name,
            keyId,
            key->pin,
            certPath);

        if (cmsVec.empty()) {
            res.status = 500;
            res.set_content(json{{"error", "CMS generation failed"}}.dump(), "application/json");
            return;
        }

        std::string cmsStr(cmsVec.begin(), cmsVec.end());
        std::string cmsB64;
        Base64::Encode(cmsStr, &cmsB64);
        res.status = 200;
        res.set_content(json{{"cms_b64", cmsB64}}.dump(), "application/json");
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Content-Type", "application/json");
        res.set_content(json{{"status", "ok"}}.dump(), "application/json");
    });

    std::cout << "Listening on http://0.0.0.0:" << config.port << std::endl;
    std::cout << "  POST /cms  - body: {\"key_id\": \"...\", \"data\": \"...\"} or \"data_b64\": \"...\"" << std::endl;
    std::cout << "  GET  /health" << std::endl;

    if (!svr.listen("0.0.0.0", config.port)) {
        std::cerr << "Failed to bind port " << config.port << std::endl;
        return 1;
    }
    return 0;
}
