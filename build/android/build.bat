@setlocal
@set PATH=%PATH%;%ANDROID_NDK%;c:\android-ndk
@ndk-build -C jni
@endlocal