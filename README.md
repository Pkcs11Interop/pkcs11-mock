PKCS11-MOCK
===========
**PKCS#11 mock module**

## Table of Contents

* [Overview](#overview)
* [Download](#download)
* [Building the source](#building-the-source)
  * [Windows](#windows)
  * [Linux](#linux)
  * [Mac OS X](#mac-os-x)
  * [Android](#android)
  * [iOS](#ios)
* [License](#license)
* [About](#about)

## Overview

PKCS11-MOCK is minimalistic C library that implements [PKCS#11 v2.20](https://github.com/Pkcs11Interop/PKCS11-SPECS/tree/master/v2.20) API. It is not a real cryptographic module but just a dummy mock object designed specifically for unit testing of [Pkcs11Interop](https://github.com/Pkcs11Interop/Pkcs11Interop) library.

The [Wikipedia article on mock objects ](https://en.wikipedia.org/wiki/Mock_object) states:

> In object-oriented programming, mock objects are simulated objects that mimic the behavior of real objects in controlled ways. A programmer typically creates a mock object to test the behavior of some other object, in much the same way that a car designer uses a crash test dummy to simulate the dynamic behavior of a human in vehicle impacts.

Following these simple principles PKCS11-MOCK does not depend on any hardware nor configuration and can be easily modified to return any response or data. It has been tested on several desktop and mobile platforms and as such might also be used as a lightweight skeleton for the development of portable PKCS#11 libraries.

## Download

Signed precompiled binaries as well as source code releases can be downloaded from [releases page](https://github.com/Pkcs11Interop/pkcs11-mock/releases).  
Archives with source code are signed with [GnuPG key of Jaroslav Imrich](https://www.jimrich.sk/crypto/).  
Windows libraries are signed with [code-signing certificate of Jaroslav Imrich](https://www.jimrich.sk/crypto/).

## Building the source

### Windows

Execute the build script on a 64-bit Windows machine with [Visual Studio 2015 Community](https://www.visualstudio.com/vs/) (or newer) installed:

	cd build/windows/
	build.bat
	
The script should use Visual Studio to build both 32-bit (`pkcs11-mock-x86.dll`) and 64-bit (`pkcs11-mock-x64.dll`) versions of the library.

### Linux

Execute the build script on a 64-bit Linux machine with GCC, GNU Make and GCC multilib support installed (available in [build-essential](http://packages.ubuntu.com/trusty/build-essential) and [gcc-multilib](http://packages.ubuntu.com/trusty/gcc-multilib) packages on Ubuntu 14.04 LTS):

	cd build/linux/
	sh build.sh

The script should use GCC to build both 32-bit (`pkcs11-mock-x86.so`) and 64-bit (`pkcs11-mock-x64.so`) versions of the library.

### Mac OS X

Execute the build script on a 64-bit Mac OS X machine with [Xcode](https://developer.apple.com/xcode/) and its "Command Line Tools" extension installed:

	cd build/osx/
	sh build.sh

The script should use GCC to build both 32-bit (`pkcs11-mock-x86.dylib`) and 64-bit (`pkcs11-mock-x64.dylib`) versions of the library.

### Android

Execute the build script on a 64-bit Windows machine with [Android NDK r14](https://developer.android.com/ndk/) (or newer) unpacked in `C:\android-ndk` folder:

	cd build/android/
	build.bat
	
The script should use Android NDK to build the library for all supported architectures. Results will be located in `libs` directory and its subdirectories.

### iOS

Execute the build script on a 64-bit Mac OS X machine with [Xcode](https://developer.apple.com/xcode/) and its "Command Line Tools" extension installed:

	cd build/ios/
	sh build.sh

The script should use Xcode to build Mach-O universal binary (`libpkcs11-mock.a`) usable on all supported architectures.

## License

PKCS11-MOCK is available under the terms of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).  
[Human friendly license summary](https://tldrlegal.com/l/apache2) is available at tldrlegal.com but the [full license text](LICENSE.md) always prevails.

## About

PKCS11-MOCK has been developed as a part of [Pkcs11Interop](https://www.pkcs11interop.net/) project by [Jaroslav Imrich](https://www.jimrich.sk/).  
Please visit project website - [pkcs11interop.net](https://www.pkcs11interop.net) - for more information.
