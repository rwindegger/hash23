cmake_minimum_required(VERSION 3.28)

CPMAddPackage("gh:google/googletest#v1.17.0")

include(GoogleTest)

add_executable(
        hash23_tests
        main.cpp
        sha2_512_tests.cpp
)

if(MSVC)
    target_compile_options(hash23_tests PRIVATE
            /W4             # Warning level 4 (almost all warnings)
            /WX             # Treat warnings as errors
            /permissive-    # Strict conformance mode
            /Zc:__cplusplus # Enable correct __cplusplus macro
            /utf-8          # UTF-8 source and execution character sets
    )

    # Debug-specific flags
    target_compile_options(hash23_tests PRIVATE
            $<$<CONFIG:Debug>:/Od>      # No optimization
            $<$<CONFIG:Debug>:/Zi>      # Debug info
            $<$<CONFIG:Debug>:/RTC1>    # Runtime checks
    )

    # RelWithDebInfo-specific flags
    target_compile_options(hash23_tests PRIVATE
            $<$<CONFIG:RelWithDebInfo>:/O2>         # Optimize for speed
            $<$<CONFIG:RelWithDebInfo>:/Zi>         # Debug info
            $<$<CONFIG:RelWithDebInfo>:/DNDEBUG>    # Define NDEBUG
    )
else()
    target_compile_options(hash23_tests PRIVATE
            -Wall           # Enable all warnings
            -Wextra         # Enable extra warnings
            -Werror         # Treat warnings as errors
            -pedantic       # Enforce strict compliance to the standard
            -Wconversion    # Warn on type conversions that may alter a value
    )

    # Debug-specific flags
    target_compile_options(hash23_tests PRIVATE
            $<$<CONFIG:Debug>:-O0>        # No optimization
            $<$<CONFIG:Debug>:-g>         # Debug info
    )

    # RelWithDebInfo-specific flags
    target_compile_options(hash23_tests PRIVATE
            $<$<CONFIG:RelWithDebInfo>:-O2>      # Optimize for speed
            $<$<CONFIG:RelWithDebInfo>:-g>       # Debug info
            $<$<CONFIG:RelWithDebInfo>:-DNDEBUG> # Define NDEBUG
    )
endif()

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
