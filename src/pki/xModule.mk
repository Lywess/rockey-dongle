LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := pki

##
##
##
LOCAL_CXXFLAGS := -Ithird_party/TASSL-1.1.1/include

##
##
##
$(call add_general_source_files_under, $(LOCAL_PATH))

##
##
##
ifneq ("$(X4C_BUILD)","native")
$(call build-library)
endif ## !native ...
