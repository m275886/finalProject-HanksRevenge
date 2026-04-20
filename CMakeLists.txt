cmake_minimum_required(VERSION 3.10)
project(Hanks_Revenge C)

add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DSECURITY_WIN32 -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000006)

set(PROJECT_HEADERS
	include/command.h
	include/error.h
	include/generated_commands.h
	include/generated_errors.h
	include/network.h
	include/process.h
	include/system.h
	include/debug.h
	include/exports.h
	include/security.h
	include/protocol.h
	include/tls.h
)

set(PROJECT_SOURCES
	src/command.c
	src/network.c
	src/process.c
	src/protocol.c
	src/security.c
	src/system.c
	src/debug.c
	src/exports.c
	src/tls.c
)


add_library(Hanks_Revenge SHARED ${PROJECT_SOURCES} ${PROJECT_HEADERS})


target_include_directories(Hanks_Revenge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(Hanks_Revenge ntdll advapi32 kernel32 ws2_32 secur32 crypt32)

target_compile_options(Hanks_Revenge PRIVATE /W4 /WX)

add_executable(HankInitialHost host/HankInitialHost.c)

target_include_directories(HankInitialHost PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(HankInitialHost kernel32)

target_compile_options(HankInitialHost PRIVATE /W4 /WX)
