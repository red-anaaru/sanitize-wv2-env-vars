cmake_minimum_required(VERSION 3.16)
project(webview2_env_sanitizer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(webview2_env_sanitizer STATIC
    webview2_env_sanitizer.hpp
    webview2_env_sanitizer.cpp
)

if(WIN32)
    target_sources(webview2_env_sanitizer PRIVATE webview2_env_sanitizer_win.cpp)
    target_link_libraries(webview2_env_sanitizer PRIVATE advapi32)
elseif(APPLE)
    target_sources(webview2_env_sanitizer PRIVATE webview2_env_sanitizer_mac.mm)
    set_source_files_properties(webview2_env_sanitizer_mac.mm
        PROPERTIES COMPILE_FLAGS "-fobjc-arc")
endif()

target_include_directories(webview2_env_sanitizer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
