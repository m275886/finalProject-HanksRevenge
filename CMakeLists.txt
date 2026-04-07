cmake_minimum_required(VERSION 3.10)
project(lab2 C)

add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN)

set(PROJECT_HEADERS
	include/command.h
	include/network.h
	include/process.h
)

set(PROJECT_SOURCES
	src/command.c
	src/network.c
	src/process.c
)



add_executable(lab2 ${PROJECT_SOURCES} ${PROJECT_HEADERS})

target_include_directories(lab2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(lab2 advapi32 kernel32 ws2_32 ntdll)


target_compile_options(lab2 PRIVATE /W4 /WX)
