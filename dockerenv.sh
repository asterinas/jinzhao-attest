#!/usr/bin/env bash

CURRDIR="$(pwd)"
WORKDIR="$(basename $CURRDIR)"

ACTION=${1}
ENVTYPE=${2#"--"} # $2: --sgxsdk|--occlum|--ubuntu
TEETYPE=${3#"--"} # $3: --sgx1|--sgx2|--hyperenclave|--csv|--tdx

DEVICE_SGX1="/dev/isgx"
DEVICE_SGX2_1="/dev/sgx_enclave"
DEVICE_SGX2_2="/dev/sgx_provision"
DEVICE_HYPERENCLAVE_1="/dev/jailhouse"
DEVICE_HYPERENCLAVE_2="/dev/hyperenclave"

VOLUME_SGX2="/dev/sgx"

TEE_DEVICES=""
TEE_VOLUMES=""

show_help() {
    echo "Usage: $(basename $0) --init|--exec|--delete [environment-type]"
}

docker_init() {
  local volumeopt=""

  for volume in $TEE_VOLUMES ; do
    volumeopt="$volumeopt -v ${volume}:${volume}"
  done
  echo "TEE Volumes: $volumeopt"

  sudo docker run  -td \
      --name $CONTAINERNAME \
      --privileged \
      --net=host \
      --cap-add=SYS_PTRACE \
      --security-opt seccomp=unconfined \
      $volumeopt \
      -v $CURRDIR:/root/$WORKDIR \
      -w /root/$WORKDIR \
      --user root \
      $IMAGE \
      bash
}

docker_exec() {
   sudo docker exec -it $CONTAINERNAME bash
}

docker_delete() {
   sudo docker rm -f $CONTAINERNAME
}

# If environment is not specified, decide it by device name
# Support sgx-epid|sgx-dcap|hyperenclave|no-tee now
if [ -z "$TEETYPE" ] ; then
    [ -e $DEVICE_SGX1 ] && TEE_DEVICES=$DEVICE_SGX1 && TEETYPE="sgx1-epid"
    [ -e $DEVICE_SGX2_1 ] && TEE_DEVICES=$DEVICE_SGX2_1 && TEETYPE="sgx2-dcap"
    [ -e $DEVICE_SGX2_2 ] && TEE_DEVICES=$DEVICE_SGX2_2 && TEETYPE="sgx2-dcap"
    [ -e $DEVICE_HYPERENCLAVE_1 ] && TEE_DEVICES=$DEVICE_HYPERENCLAVE_1 && TEETYPE="hyperenclave"
    [ -e $DEVICE_HYPERENCLAVE_2 ] && TEE_DEVICES=$DEVICE_HYPERENCLAVE_2 && TEETYPE="hyperenclave"
    [ -z "$TEETYPE" ] && TEETYPE="no-tee"
fi
if [ -z "$ENVTYPE" ] ; then
    ENVTYPE="sgxsdk"
fi

echo "TEE Devices: $TEE_DEVICES"
echo "TEE Type: $TEETYPE"
echo "Environment: $ENVTYPE"

if [ "$ENVTYPE" == "sgxsdk" ] ; then
case "$TEETYPE" in
    sgx1-epid)
        IMAGE="antkubetee/kubetee-dev-ubuntu18.04-grpc-sgx-ssl:2.0"
        ;;
    sgx2-dcap)
        IMAGE="antkubetee/kubetee-dev-sgx:2.0-ubuntu20.04-sgx2.17.1"
        TEE_VOLUMES="$VOLUME_SGX2"
        ;;
    hyperenclave)
        IMAGE="antkubetee/kubetee-dev-hyperenclave:1.0-ubuntu20.04-sgx2.15.1"
        ;;
    --no-tee)
        IMAGE="antkubetee/kubetee-dev-ubuntu18.04-grpc-non-sgx:1.0"
        ;;
    *)
        echo "Unsupported TEE type: $TEETYPE"
        exit 1
        ;;
esac
elif [ "$ENVTYPE" == "occlum" ] ; then
case "$TEETYPE" in
    sgx1-epid)
        IMAGE="occlum/occlum:0.19.0-ubuntu18.04"
        ;;
    sgx2-dcap)
        IMAGE="occlum/occlum:latest-ubuntu20.04"
        TEE_VOLUMES="$VOLUME_SGX2"
        ;;
    hyperenclave)
        IMAGE="TBD:incoming"
        ;;
    *)
        echo "Unsupported tee type for Occlum environment: $TEETYPE"
        exit 1
        ;;
esac
elif [ "$ENVTYPE" == "ubuntu" ] ; then
    IMAGE="antkubetee/kubetee-dev-base:2.0-ubuntu20.04-gprc-1.24.3"
else
    echo "Unsupported environment type: $ENVTYPE" ; exit 1
fi

CONTAINERNAME="jinattest-${ENVTYPE}-${TEETYPE}-${WORKDIR}-$(whoami)"

echo "IMAGE: $IMAGE"
echo "CONTAINERNAME: $CONTAINERNAME"

case "$ACTION" in
    --init)     docker_init ;;
    --exec)     docker_exec ;;
    --delete)   docker_delete ;;
    -h|--help)  show_help ; exit 0 ;;
    *)          show_help ; exit 1 ;;
esac
