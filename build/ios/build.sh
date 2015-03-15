#!/bin/sh

set -e

rm -Rf build
rm -Rf pkcs11-mock*.a

xcodebuild -project pkcs11-mock.xcodeproj -target pkcs11-mock -sdk iphonesimulator -configuration Release clean build
cp build/Release-iphonesimulator/libpkcs11-mock.a libpkcs11-mock-i386.a

xcodebuild -project pkcs11-mock.xcodeproj -target pkcs11-mock -sdk iphoneos -configuration Release clean build
cp build/Release-iphoneos/libpkcs11-mock.a libpkcs11-mock-arm.a

lipo -create -output libpkcs11-mock.a libpkcs11-mock-i386.a libpkcs11-mock-arm.a
