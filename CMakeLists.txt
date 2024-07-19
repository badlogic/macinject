cmake_minimum_required(VERSION 3.10)

project(macinject)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_executable(macinject ${SOURCES})
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.14")

# Define the entitlements file
set(ENTITLEMENTS_FILE "${CMAKE_SOURCE_DIR}/entitlements.plist")

# Add necessary frameworks
target_link_libraries(macinject
    "-framework CoreFoundation"
    "-framework CoreServices"
    "-framework Security"
)

# Apply entitlements after build
add_custom_command(TARGET macinject POST_BUILD
    COMMAND codesign --entitlements ${ENTITLEMENTS_FILE} -s "Apple Development" $<TARGET_FILE:macinject>
)

file(GLOB_RECURSE TEST_SOURCES "test/*.cpp")
add_executable(test ${TEST_SOURCES})
set_target_properties(test PROPERTIES COMPILE_FLAGS "-O0 -g")

