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
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <algorithm>
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

/** Создаёт директорию и все родительские (если нужно). */
static bool ensureDirExists(const std::string& dir) {
    if (dir.empty()) return true;
    size_t last = dir.find_last_of("/\\");
    if (last != std::string::npos && last > 0) {
        std::string parent = dir.substr(0, last);
        if (parent.size() <= 2 && parent.find(':') != std::string::npos)
            ; // корень диска (C:), не создаём
        else if (!ensureDirExists(parent))
            return false;
    }
    int nw = MultiByteToWideChar(CP_UTF8, 0, dir.c_str(), -1, NULL, 0);
    if (nw <= 0) return false;
    std::vector<wchar_t> wdir(nw);
    MultiByteToWideChar(CP_UTF8, 0, dir.c_str(), -1, wdir.data(), nw);
    return CreateDirectoryW(wdir.data(), NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}

/** Создаёт родительскую директорию для path (например logs для logs/service.log). */
static bool ensureParentDirExists(const std::string& path) {
    size_t last = path.find_last_of("/\\");
    if (last == std::string::npos) return true;
    std::string dir = path.substr(0, last);
    return ensureDirExists(dir);
}

/** Делает путь к лог-файлу абсолютным относительно директории exe, если путь относительный. */
static std::string resolveLogPath(const std::string& configuredPath, const std::string& exeDir) {
    if (configuredPath.empty()) return exeDir + "\\logs\\service.log";
    if (configuredPath.size() >= 2 && configuredPath[1] == ':') return configuredPath; // absolute Windows
    if (configuredPath[0] == '/') return configuredPath; // absolute Unix
    std::string p = exeDir + "\\" + configuredPath;
    for (size_t i = 0; i < p.size(); ++i) if (p[i] == '/') p[i] = '\\';
    return p;
}

/** Путь к логам в %LOCALAPPDATA% (не требует прав записи в Program Files). */
static std::string getLocalAppDataLogPath() {
    wchar_t buf[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) == 0)
        return "logs\\service.log";
    int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return "logs\\service.log";
    std::string local(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, &local[0], n, NULL, NULL);
    return local + "\\token-signer\\logs\\service.log";
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

    // Директория exe для разрешения относительных путей
    std::string exeDir;
    {
        wchar_t exePath[MAX_PATH] = {};
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) != 0) {
            std::wstring wdir(exePath);
            size_t last = wdir.find_last_of(L"\\/");
            if (last != std::wstring::npos) wdir.resize(last);
            int n = WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, NULL, 0, NULL, NULL);
            if (n > 0) { exeDir.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, &exeDir[0], n, NULL, NULL); }
        }
    }

    std::string logPath = resolveLogPath(config.log_file, exeDir);
    if (!ensureParentDirExists(logPath)) {
        // При установке в Program Files нет прав на создание папки — пишем в %LOCALAPPDATA%
        logPath = getLocalAppDataLogPath();
        if (!ensureParentDirExists(logPath)) {
            std::cerr << "Failed to create log directory for " << logPath << std::endl;
            return 1;
        }
        std::cerr << "Log directory created in LOCALAPPDATA: " << logPath << std::endl;
    }
    // Ротация: по размеру, приближённо log_max_lines строк (~120 байт на строку)
    size_t maxSize = static_cast<size_t>(std::max(1000, config.log_max_lines)) * 120u;
    int maxFiles = std::max(1, std::min(10, config.log_max_files));
    auto createLogger = [&](const std::string& path) {
        return std::make_shared<spdlog::sinks::rotating_file_sink_mt>(path, maxSize, static_cast<size_t>(maxFiles));
    };
    try {
        auto sink = createLogger(logPath);
        auto logger = std::make_shared<spdlog::logger>("service", sink);
        logger->set_level(spdlog::level::info);
        logger->flush_on(spdlog::level::info);
        spdlog::set_default_logger(logger);
    } catch (const std::exception& e) {
        // Нет прав на запись в Program Files — переходим в %LOCALAPPDATA%
        logPath = getLocalAppDataLogPath();
        if (!ensureParentDirExists(logPath)) {
            std::cerr << "Failed to create log directory for " << logPath << std::endl;
            return 1;
        }
        try {
            auto sink = createLogger(logPath);
            auto logger = std::make_shared<spdlog::logger>("service", sink);
            logger->set_level(spdlog::level::info);
            logger->flush_on(spdlog::level::info);
            spdlog::set_default_logger(logger);
            std::cerr << "Logs (no write access to install dir): " << logPath << std::endl;
        } catch (const std::exception& e2) {
            std::cerr << "Failed to open log file " << logPath << ": " << e2.what() << std::endl;
            return 1;
        }
    }

    spdlog::info("Config loaded: port={}, keys={}", config.port, config.keys.size());

    httplib::Server svr;

    svr.Post("/api/v1/create_cms", [&config](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "application/json; charset=utf-8");

        json body;
        try {
            body = json::parse(req.body);
        } catch (const json::exception&) {
            spdlog::warn("Invalid JSON in request body");
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
            spdlog::warn("Unknown or invalid key_id: {}", keyId);
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
            spdlog::error("CMS generation failed for key_id={}", keyId);
            res.status = 500;
            res.set_content(json{{"error", "CMS generation failed"}}.dump(), "application/json");
            return;
        }
        spdlog::info("CMS created for key_id={}, size={}", keyId, cmsVec.size());

        std::string cmsStr(cmsVec.begin(), cmsVec.end());
        std::string cmsB64;
        Base64::Encode(cmsStr, &cmsB64);
        res.status = 200;
        res.set_content(json{{"cms", cmsB64}}.dump(), "application/json");
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Content-Type", "application/json");
        res.set_content(json{{"status", "ok"}}.dump(), "application/json");
    });

    spdlog::info("Listening on http://0.0.0.0:{}", config.port);
    spdlog::info("  POST /api/v1/create_cms  GET /health");

    if (!svr.listen("0.0.0.0", config.port)) {
        spdlog::error("Failed to bind port {}", config.port);
        return 1;
    }
    return 0;
}
