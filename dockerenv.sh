#!/usr/bin/env bash

CURRDIR="$(pwd)"
WORKDIR="$(basename $CURRDIR)"

ACTION=${1}
ENVTYPE=${2#"--"} # $2: --sgxsdk|--occlum|--ubuntu
TEETYPE=${3#"--"} # $3: --sgx1|--sgx2|--hyperenclave|--csv|--tdx

DEVICE_SGX1="isgx"
DEVICE_SGX2="sgx_enclave sgx_provision"
DEVICE_HYPERENCLAVE="jailhouse"

VOLUME_SGX2="/dev/sgx"

TEE_DEVICES=""
TEE_VOLUMES=""

show_help() {
    echo "Usage: $(basename $0) --init|--exec|--delete [environment-type]"
}

docker_init() {
  local devopt=""
  local volumeopt=""

  for dev in $TEE_DEVICES ; do
    devopt="$devopt --device /dev/$dev"
  done
  echo "TEE Devices: $devopt"

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
      $devopt \
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
    [ -e /dev/$(echo $DEVICE_SGX1 | awk '{print $1}') ] && TEETYPE="sgx1-epid"
    [ -e /dev/$(echo $DEVICE_SGX2 | awk '{print $1}') ] && TEETYPE="sgx2-dcap"
    [ -e /dev/$(echo $DEVICE_HYPERENCLAVE | awk '{print $1}') ] && TEETYPE="hyperenclave"
    [ -z "$TEETYPE" ] && TEETYPE="no-tee"
fi
if [ -z "$ENVTYPE" ] ; then
    ENVTYPE="sgxsdk"
fi

echo "TEE Type: $TEETYPE"
echo "Environment: $ENVTYPE"

if [ "$ENVTYPE" == "sgxsdk" ] ; then
case "$TEETYPE" in
    sgx1-epid)
        IMAGE="antkubetee/kubetee-dev-ubuntu18.04-grpc-sgx-ssl:2.0"
        TEE_DEVICES="$DEVICE_SGX1"
        ;;
    sgx2-dcap)
        IMAGE="antkubetee/kubetee-dev-sgx:2.0-ubuntu20.04-sgx2.17.1"
        TEE_DEVICES="$DEVICE_SGX2"
        TEE_VOLUMES="$VOLUME_SGX2"
        ;;
    hyperenclave)
        IMAGE="antkubetee/kubetee-dev-hyperenclave:1.0-ubuntu20.04-sgx2.15.1"
        TEE_DEVICES="$DEVICE_HYPERENCLAVE"
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
        TEE_DEVICES="$DEVICE_SGX1"
        ;;
    sgx2-dcap)
        IMAGE="occlum/occlum:0.29.3-ubuntu20.04"
        TEE_DEVICES="$DEVICE_SGX2"
        TEE_VOLUMES="$VOLUME_SGX2"
        ;;
    hyperenclave)
        IMAGE="TBD:incoming"
        TEE_DEVICES="$DEVICE_HYPERENCLAVE"
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
