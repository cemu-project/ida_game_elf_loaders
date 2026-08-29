# ida_game_elf_loaders
A collection of user mode ELF loaders for the following game consoles:
* ~~PS3~~
* ~~PS Vita~~
* Wii U

You should use other repositories for the non-Wii U ELF loaders, as this one is only aimed at providing an updated version of the RPX loader.

## Installation
Copy loader plugins to IDA loaders directory.

## Building

### Dependencies
* IDA SDK
* [CMake](https://cmake.org/download/)

### Generate Projects With CMake
The IDA cmake module included will expect to find the IDA SDK in an `IDA_SDK_DIR` or `IDA_SDK` environment variable.
If you would like to generate 64-bit EA targeted loaders, you need to add `-D IDA_64_BIT_EA_T=YES` to cmake command line.

Navigate to the directory of the loader you would like to build in 'src/', then run the following command

`mkdir build && cd build && cmake ../`

This should create a build directory with your generated project files.

### Building
Optionally, you can also build using cmake with the following command

`cmake --build ./`

## Notes

The current commit was compiled and tested to work with IDA 9.4.
It also comes with improved Wii U RPX/RPL support, including compressed sections,
FILE_INFO parsing, import/export metadata, and a broader set of relocations.
