#!/usr/bin/env bash

# Check whether there is sgx device
if [ -e /dev/isgx ] ; then
    echo "Found sgx1 device"
    AESM_SERVICE_DIR="/opt/intel/sgxpsw/aesm"
elif [ -e /dev/sgx_enclave -o -e /dev/sgx/enclave ] ; then
    echo "Found sgx2 device"
    AESM_SERVICE_DIR="/opt/intel/sgx-aesm-service/aesm"
else
    echo "There is no sgx device"
    exit 1
fi

# Start aesmd if it is not running
if ! pgrep "aesm_service" > /dev/null ; then
    echo "Start aesmd service ..."
    LD_LIBRARY_PATH="/usr/local/lib:/usr/lib64:${AESM_SERVICE_DIR}:$LD_LIBRARY_PATH" \
        $AESM_SERVICE_DIR/aesm_service
else
    echo "aesmd service is already started"
fi
