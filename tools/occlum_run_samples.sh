#!/usr/bin/env bash

THISDIR="$(dirname $(readlink -f $0))"
ACTIONS="${1:-all}"

# Specify the libc, "musl" as default, "glibc" is equal to "gnu"
OCCLUM_LIBC="${2:-gnu}"
[ "$OCCLUM_LIBC" == "glibc" ] && OCCLUM_LIBC="gnu"

OCCLUM_INSTANCE_DIR="$THISDIR/occlum-instance"
COPYBOM="/opt/occlum/build/bin/copy_bom"

# 1. Init Occlum Workspace
if [ "$ACTIONS" == "all" -o "$ACTIONS" == "init" ] ; then
  rm -rf $OCCLUM_INSTANCE_DIR && \
  mkdir -p $OCCLUM_INSTANCE_DIR && \
  cd $OCCLUM_INSTANCE_DIR && occlum init || exit 1
fi

# 2. Copy files into Occlum Workspace and Build
if [ "$ACTIONS" == "all" -o "$ACTIONS" == "build" ] ; then
  cd $OCCLUM_INSTANCE_DIR

  # Prepare files by copy_bom tool
  OCCLUM_LOG_LEVEL=info \
  $COPYBOM --include-dir /opt/occlum/etc/template \
      --file ${THISDIR}/bom_samples_${OCCLUM_LIBC}.yaml \
      --root ./image

  new_json="$(jq '.env.default += ["LD_LIBRARY_PATH=/opt/occlum/glibc/lib"]' Occlum.json)" && \
  echo "${new_json}" > Occlum.json

  # Add PCCS env
  if [ -n "$UA_ENV_PCCS_URL" ] ; then
    new_json="$(jq .env.default+=[\"UA_ENV_PCCS_URL=$UA_ENV_PCCS_URL\"] Occlum.json)" && \
    echo "${new_json}" > Occlum.json
    echo "{\"pccs_url\":\"$UA_ENV_PCCS_URL\", \"use_secure_cert\":false}" > /etc/sgx_default_qcnl.conf
  fi

  occlum build
fi

# 3. Run application
# export OCCLUM_LOG_LEVEL=debug
if [ "$ACTIONS" == "all" -o "$ACTIONS" == "run" ] ; then
  cd $OCCLUM_INSTANCE_DIR && \
  occlum run /bin/app-sample-unified-attestation-generation
  occlum run /bin/app-sample-unified-attestation-verification-untrusted
  occlum run /bin/app-sample-unified-attestation-nested-report
  occlum run /bin/app-sample-unified-attestation-instance-ree
fi
