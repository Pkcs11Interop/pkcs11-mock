LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := pkcs11-mock
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../../src
LOCAL_SRC_FILES := $(LOCAL_PATH)/../../../src/pkcs11-mock.c
LOCAL_LDFLAGS += -Wl,--version-script,$(LOCAL_PATH)/pkcs11-mock.version
include $(BUILD_SHARED_LIBRARY)
