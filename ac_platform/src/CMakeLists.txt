cmake_minimum_required(VERSION 2.6)

set(PROJECT_NAME "ac_platform")

project(${PROJECT_NAME})

#set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(CMAKE_CXX_FLAGS "-lm -lpthread -lssl -lcrypto -luci -lcurl")
#set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0 -fsanitize=address -fno-omit-frame-pointer -fsanitize=leak")
#set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

add_compile_options(-fno-stack-protector -Wno-unused-but-set-variable)

file(GLOB_RECURSE SOURCE_FILES  ${PROJECT_SOURCE_DIR}/*.c)

#EXCLUDE CMakeList files
list(FILTER SOURCE_FILES EXCLUDE REGEX "feature_tests.")
list(FILTER SOURCE_FILES EXCLUDE REGEX "CMakeCCompilerId.")

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} curl uci)

install(PROGRAMS ${PROJECT_NAME} DESTINATION /usr/sbin)
