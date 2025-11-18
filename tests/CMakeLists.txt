cmake_minimum_required(VERSION 3.28)

CPMAddPackage("gh:google/googletest#v1.17.0")

include(GoogleTest)

add_executable(
        hash23_tests
        main.cpp
        sha2_512_tests.cpp
)

target_link_libraries(
        hash23_tests
        PRIVATE
        hash23::hash23
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(hash23_tests)

set_target_properties(hash23_tests PROPERTIES CXX_STANDARD 23)
target_compile_features(hash23_tests PUBLIC cxx_std_23)
