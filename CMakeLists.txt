cmake_minimum_required(VERSION 3.14)
project(CmsCreator LANGUAGES CXX)

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
)

if(WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE
    kernel32
    crypt32
  )
elseif(UNIX)
  target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()
