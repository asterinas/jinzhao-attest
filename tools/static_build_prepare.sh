#!/usr/bin/env bash

set -e

THISDIR="$(dirname $(readlink -f $0))"

STATICDIR="$THISDIR/static"
INSTALLDIR="$STATICDIR/install"

ALL_COMPONENTS="openssl libcurl protobuf"
OPENSSLDIR=openssl
CURLDIR=curl
PROTOBUFDIR=protobuf

SHOW_HELP() {
    LOG_INFO "Usage: $0 [component-name]\n"
    LOG_INFO "Build component in [$ALL_COMPONENTS] or all by default\n"
    exit 0
}

LOG_DEBUG() {
    echo -e "\033[36m$@\033[0m"
}

LOG_INFO() {
    echo -e "\033[32m$@\033[0m"
}

LOG_ERROR() {
    echo -e "\033[31m$@\033[0m"
}

ERROR_EXIT() {
  LOG_ERROR "$@" && exit 1
}

TRYGET() {
    local dst=$1
    local url=$2
    local pkg=${3:-$(basename $url)}
    local flag="./occlum_demo_source"

    # Download package tarball
    if [ ! -e $pkg ] ; then
        LOG_DEBUG "Downloading $pkg ..."
        wget $url -O $pkg || ERROR_EXIT "Fail to download $pkg"
    else
        LOG_INFO "[READY] $pkg source package file"
    fi

    # Prepare the source code directory
    if [ ! -f $dst/$flag ] ; then
        LOG_DEBUG "Preparing source code: $dst ..."
        mkdir -p $dst && \
        tar -xvf $pkg -C $dst --strip-components 1 >/dev/null || \
        ERROR_EXIT "Fail to extract archive file $pkg"
        touch $dst/$flag && \
        LOG_DEBUG "Prepare $(basename $dst) source code successfully"
    else
        LOG_INFO "[READY] $dst source directory"
    fi
}

openssl_check() {
    [ -f "$INSTALLDIR/lib/libcrypto.a" ] || return 1
}

openssl_build() {
    cd $STATICDIR/$OPENSSLDIR && \
    ./config --prefix=$INSTALLDIR \
      --with-rand-seed=rdcpu \
      no-zlib no-async no-tests enable-egd && \
    make -j && make install && \
    cp ./libcrypto.a $INSTALLDIR/lib/ && \
    cp ./libssl.a $INSTALLDIR/lib/
}

libcurl_check() {
    [ -f "$INSTALLDIR/lib/libcurl.a" ] || return 1
}

libcurl_build() {
    cd $STATICDIR/$CURLDIR
    if [ ! -f ./configure ] ; then
      LOG_DEBUG "Building configure file ..."
      ./buildconf || exit 1
    fi
    ./configure \
      --prefix=$INSTALLDIR \
      --with-ssl=$INSTALLDIR \
      --without-zlib && \
    make -j && make install
}

protobuf_check() {
    [ -f "$INSTALLDIR/lib/libprotobuf.a" ] || return 1
}

protobuf_build() {
    cd $STATICDIR/$PROTOBUFDIR/cmake && \
    rm -rf build && mkdir -p build && cd build && \
    cmake ../ \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -Dprotobuf_BUILD_TESTS=OFF       \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
        -DCMAKE_BUILD_TYPE=Release &&    \
    make -j && make install
}

# Show help menu
[ "$1" == "-h" -o "$1" == "--help" ] && SHOW_HELP

# Check the build mode
BUILDMODE="Release"
BUILDVERBOSE=""
if [ "$1" == "--debug" ] ; then
  BUILDMODE="Debug"
  BUILDVERBOSE="VERBOSE=1"
  shift;
fi

# Check the force build option
BUILDFORCE="NO"
if [ "$1" == "--force" ] ; then
  BUILDFORCE="YES"
  shift;
fi

# Build specified component or all by default
BUILD_COMPONENTS="${1:-$ALL_COMPONENTS}"

# Download all components once here together
mkdir -p $STATICDIR && cd $STATICDIR || exit 1
TRYGET $OPENSSLDIR https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1k.tar.gz
TRYGET $CURLDIR https://github.com/curl/curl/archive/curl-7_70_0.tar.gz
TRYGET $PROTOBUFDIR https://github.com/protocolbuffers/protobuf/releases/download/v21.6/protobuf-all-21.6.tar.gz

for i in $BUILD_COMPONENTS ; do
    if [ "$BUILDFORCE" == "NO" ] ; then
        ${i}_check && LOG_INFO "[READY] build check for $i" && continue
    fi
    LOG_DEBUG "Building $i ..." && ${i}_build && \
    LOG_DEBUG "Build $i successfully" || ERROR_EXIT "Fail to build $i"
done

echo "Copy all static libraries into system directory: /usr/lib64"
cp $INSTALLDIR/lib/*.a /usr/lib64/
