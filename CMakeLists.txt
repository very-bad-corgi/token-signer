cmake_minimum_required(VERSION 3.14)
project(token-signer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-DUNICODE -D_UNICODE)

include(FetchContent)

# nlohmann/json
FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# yaml-cpp
FetchContent_Declare(yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG        yaml-cpp-0.7.0
)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)

# cpp-httplib (single header)
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.14.3
)
FetchContent_Populate(httplib)

# base64 (tkislan, header-only)
FetchContent_Declare(base64
  GIT_REPOSITORY https://github.com/tkislan/base64.git
  GIT_TAG        master
)
FetchContent_Populate(base64)

# spdlog
FetchContent_Declare(spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.13.0
)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(spdlog)

include_directories(src src/include src/avpass)

file(GLOB_RECURSE SOURCE_FILES "src/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PRIVATE
  ${json_SOURCE_DIR}/include
  ${httplib_SOURCE_DIR}
  ${base64_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  nlohmann_json::nlohmann_json
  yaml-cpp
  spdlog::spdlog
)

if(WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE
    kernel32
    crypt32
  )
elseif(UNIX)
  target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()

# --- Install & CPack (инсталлятор) ---
include(GNUInstallDirs)

install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION bin
)

install(FILES "${CMAKE_SOURCE_DIR}/config.yaml"
  DESTINATION bin
  RENAME config.yaml
)

# Пустой каталог logs и файл service.log — в комплекте, не нужно создавать при первом запуске
install(DIRECTORY "${CMAKE_SOURCE_DIR}/logs"
  DESTINATION bin
)

# Пример конфига в документации (опционально)
# install(DIRECTORY etc/ DESTINATION etc OPTIONAL)

# Переменные CPack — обязательно ДО include(CPack), иначе кэш не обновится
set(CPACK_PACKAGE_NAME "token-signer")
set(CPACK_PACKAGE_VENDOR "ArtopiasLab")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Микросервис подписания CMS (REST API)")
set(CPACK_PACKAGE_VERSION "0.1.1")
if(WIN32)
  set(CPACK_GENERATOR "NSIS;ZIP")
  set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win64")
  set(CPACK_NSIS_MODIFY_PATH ON)
  set(CPACK_NSIS_DISPLAY_NAME "Token Signer CMS Service")
  set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES")
  # Двойной слэш: в NSIS \t = таб, поэтому нужен \\ чтобы получить один \ в пути
set(CPACK_PACKAGE_INSTALL_DIRECTORY "ArtopiasLab\\\\token-signer-${CPACK_PACKAGE_VERSION}")
else()
  set(CPACK_GENERATOR "TGZ")
  set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-linux")
endif()

include(CPack)
