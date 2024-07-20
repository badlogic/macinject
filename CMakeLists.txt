cmake_minimum_required(VERSION 3.10)

project(macinject)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.14")

# Test program
file(GLOB_RECURSE TEST_SOURCES "test/*.cpp")
add_executable(test ${TEST_SOURCES})
set_target_properties(test PROPERTIES COMPILE_FLAGS "-O0 -g -fpatchable-function-entry=4,0")

# Injection program
file(GLOB_RECURSE SOURCES "src/*.cpp")
add_executable(macinject ${SOURCES})

add_custom_command(TARGET macinject POST_BUILD
    COMMAND codesign --entitlements "${CMAKE_SOURCE_DIR}/entitlements.plist" -s "Apple Development" $<TARGET_FILE:macinject>
)