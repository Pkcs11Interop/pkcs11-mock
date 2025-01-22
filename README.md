PKCS11-MOCK
===========
**PKCS#11 mock module**

## Table of Contents

* [Overview](#overview)
* [Download](#download)
* [Building the source](#building-the-source)
  * [Windows](#windows)
  * [Linux](#linux)
  * [macOS](#macos)
  * [Android](#android)
  * [iOS](#ios)
* [License](#license)
* [About](#about)

## Overview

PKCS11-MOCK is minimalistic C library that implements [PKCS#11 v3.1](https://github.com/Pkcs11Interop/PKCS11-SPECS/tree/master/v3.1) API. It is not a real cryptographic module but just a dummy mock object designed specifically for unit testing of [Pkcs11Interop](https://github.com/Pkcs11Interop/Pkcs11Interop) library.

The [Wikipedia article on mock objects ](https://en.wikipedia.org/wiki/Mock_object) states:

> In object-oriented programming, mock objects are simulated objects that mimic the behavior of real objects in controlled ways. A programmer typically creates a mock object to test the behavior of some other object, in much the same way that a car designer uses a crash test dummy to simulate the dynamic behavior of a human in vehicle impacts.

Following these simple principles PKCS11-MOCK does not depend on any hardware nor configuration and can be easily modified to return any response or data.

## Download

Signed precompiled binaries as well as source code releases can be downloaded from [releases page](https://github.com/Pkcs11Interop/pkcs11-mock/releases).  
Archives with source code are signed with [GnuPG key of Jaroslav Imrich](https://www.jimrich.sk/crypto/).  
Windows libraries are signed with [code-signing certificate of Jaroslav Imrich](https://www.jimrich.sk/crypto/).

## Building the source

### Windows

Execute the build script on a 64-bit Windows machine with [Visual Studio 2022 Community](https://visualstudio.microsoft.com/vs/community/) (or newer) installed:

```
cd build/windows/
build.bat
```
	
The script should use Visual Studio to build both 32-bit (`pkcs11-mock-x86.dll`) and 64-bit (`pkcs11-mock-x64.dll`) versions of the library.

### Linux

Execute the build script on a 64-bit Linux machine with GCC, GNU Make and GCC multilib support installed (available in [build-essential](https://packages.ubuntu.com/noble/build-essential) and [gcc-multilib](https://packages.ubuntu.com/noble/gcc-multilib) packages on Ubuntu 24.04 LTS):

```
cd build/linux/
sh build.sh
```

The script should use GCC to build both 32-bit (`pkcs11-mock-x86.so`) and 64-bit (`pkcs11-mock-x64.so`) versions of the library.

### macOS

Execute the build script on a 64-bit macOS machine with [Xcode](https://developer.apple.com/xcode/) and its "Command Line Tools" extension installed:

```
cd build/macos/
sh build.sh
```

The script should use Clang to build Mach-O universal binary (`pkcs11-mock.dylib`) usable on both Apple silicon and Intel-based Mac computers.

### Android

Execute the build script on a 64-bit Windows machine with [Android NDK r26d](https://developer.android.com/ndk/) (or newer) unpacked in `C:\android-ndk` folder:

```
cd build/android/
build.bat
```
	
The script should use Android NDK to build the library for all supported architectures. Results will be located in `libs` directory and its subdirectories.

### iOS

Execute the build script on a 64-bit macOS machine with [Xcode](https://developer.apple.com/xcode/) and its "Command Line Tools" extension installed:

```
cd build/ios/
sh build.sh
```

The script should use Xcode to build the library with iphonesimulator SDK (`libpkcs11-mock-iphonesimulator.a`) and iphoneos SDK (`libpkcs11-mock-iphoneos.a`).

## License

PKCS11-MOCK is available under the terms of the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
[Human friendly license summary](https://www.tldrlegal.com/license/apache-license-2-0-apache-2-0) is available at tldrlegal.com but the [full license text](LICENSE.md) always prevails.

## About

PKCS11-MOCK has been written for the [Pkcs11Interop](https://www.pkcs11interop.net/) project by [Jaroslav Imrich](https://www.jimrich.sk/).  
Please visit project website - [pkcs11interop.net](https://www.pkcs11interop.net) - for more information.
