cmake_minimum_required(VERSION 3.10)
project(Hanks_Revenge C)

add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN)

set(PROJECT_HEADERS
	include/command.h
	include/error.h	
	include/generated_commands.h
	include/network.h
	include/process.h
	include/system.h
	include/debug.h 
	include/exports.h 
	include/security.h
	include/protocol.h
)

set(PROJECT_SOURCES
	src/command.c
	src/network.c
	src/process.c
	src/protocol.c
)


add_library(lab3 SHARED ${PROJECT_SOURCES} ${PROJECT_HEADERS})
add_dependencies(lab3 generate_shared_defs)

target_include_directories(lab3 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(lab3 ntdll advapi32 kernel32 ws2_32)

target_compile_options(lab3 PRIVATE /W4 /WX)

add_executable(lab3_host host/lab3_host.c)

target_include_directories(lab3_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(lab3_host kernel32)

target_compile_options(lab3_host PRIVATE /W4 /WX)