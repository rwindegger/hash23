from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMakeToolchain, CMakeDeps, CMake

class hash23(ConanFile):
    name = "hash23"
    version = "1.1"

    license = "MIT"
    author = "Rene Windegger <rene@windegger.wtf>"
    url = "https://github.com/rwindegger/hash23"
    description = "This library contains various hashing algorithms written in modern C++."
    topics = ("hashing", "hash", "sha512", "sha512-hash", "sha2-512")

    settings = "os", "compiler", "build_type", "arch"

    exports_sources = ( "CMakeLists.txt", "include/*", "tests/*", "cmake/*" )

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def requirements(self):
        requirements = self.conan_data.get('requirements', [])
        for requirement in requirements:
            self.requires(requirement)
