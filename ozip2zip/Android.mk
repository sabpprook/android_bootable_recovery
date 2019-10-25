LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := ozip2zip
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := ozip2zip.c
LOCAL_C_INCLUDES := external/boringssl/src/include
LOCAL_SHARED_LIBRARIES := libcrypto
include $(BUILD_EXECUTABLE)
