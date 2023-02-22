#!/usr/bin/env bash

set -e

THISDIR="$(dirname $(readlink -f $0))"

DEPSDIR="$THISDIR/deps"

ALL_COMPONENTS="openssl libcurl cares protobuf grpc"
OPENSSLDIR=openssl
CURLDIR=curl
PROTOBUFDIR=protobuf
CARESDIR=cares
GRPCDIR=grpc

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

GITGET_GRPC() {
    GRPC_SRC_DIR=$DEPSDIR/$GRPCDIR
    if [ -d $GRPC_SRC_DIR/third_party/protobuf/cmake ] ; then
        LOG_INFO "[READY] grpc"
        return 0
    fi

    LOG_DEBUG "Preparing source code: grpc ..."
    #rm -rf $GRPC_SRC_DIR && \
    mkdir -p $GRPC_SRC_DIR && cd $GRPC_SRC_DIR
    git clone https://github.com/grpc/grpc.git .
    git checkout tags/v1.24.3
    #git submodule update --init --recursive
    cd $GRPC_SRC_DIR/third_party/cares/cares
    git submodule update --init .
    git checkout tags/cares-1_15_0
    cd $GRPC_SRC_DIR/third_party/protobuf
    git submodule update --init .
    git checkout tags/v3.21.6
    cd $GRPC_SRC_DIR/third_party/abseil-cpp
    git submodule update --init .
    return 0
}

openssl_check() {
    [ -f "$OCCLUMINSTALLDIR/lib/libcrypto.so.1.1" ] || \
    [ -f "$OCCLUMINSTALLDIR/lib64/libcrypto.so.1.1" ] || \
    return 1
}

openssl_build() {
    cd "$DEPSDIR/$OPENSSLDIR" && \
    ./config --prefix=$OCCLUMINSTALLDIR \
      --openssldir=/usr/local/occlum/ssl \
      --with-rand-seed=rdcpu \
      no-zlib no-async no-tests enable-egd && \
    make -j && make install
}

libcurl_check() {
    [ -f "$OCCLUMINSTALLDIR/lib/libcurl.so" ] || \
    [ -f "$OCCLUMINSTALLDIR/lib64/libcurl.so" ] || \
    return 1
}

libcurl_build() {
    cd "$DEPSDIR/$CURLDIR"
    if [ ! -f ./configure ] ; then
      LOG_DEBUG "Building configure file ..."
      ./buildconf || exit 1
    fi
    ./configure \
      --prefix=$OCCLUMINSTALLDIR \
      --with-ssl=$OCCLUMINSTALLDIR \
      --without-zlib && \
    make -j && make install
}

protobuf_check() {
    [ -f "$INSTALLDIR/lib/libprotobuf.so.32" ] || \
    [ -f "$INSTALLDIR/lib64/libprotobuf.so.32" ] || \
    [ -f "/usr/lib/x86_64-linux-gnu/libprotobuf.so.32" ] || \
    return 1
}

protobuf_build() {
    echo "======== Building protobuf ... ========" && \
    cd $DEPSDIR/$GRPCDIR/third_party/protobuf/cmake && \
    rm -rf build && mkdir -p build && cd build && \
    cmake ../ \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -Dprotobuf_BUILD_TESTS=OFF       \
        -DBUILD_SHARED_LIBS=TRUE         \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
        -DCMAKE_BUILD_TYPE=Release &&    \
    make -j && \
    make install
}

cares_check() {
    [ -f "$INSTALLDIR/lib/libcares.so" ] || return 1
}

cares_build() {
    echo "======== Building cares ... ========" && \
    cd $DEPSDIR/$GRPCDIR/third_party/cares/cares/ && \
    rm -rf build && mkdir -p build && cd build && \
    cmake ../ \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
	    -DCMAKE_BUILD_TYPE=Release &&    \
    make -j && \
    make install
}

grpc_check() {
    [ -f "$INSTALLDIR/lib/libgrpc.so" ] || return 1
}

grpc_build() {
    echo "======== Building grpc ... ========" && \
    cd $DEPSDIR/$GRPCDIR/cmake && \
    rm -rf build && mkdir -p build && cd build && \
    cmake ../.. \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -DgRPC_INSTALL=ON                \
        -DBUILD_SHARED_LIBS=TRUE         \
        -DgRPC_CARES_PROVIDER=package    \
        -DgRPC_PROTOBUF_PROVIDER=package \
        -DgRPC_SSL_PROVIDER=package      \
        -DgRPC_ZLIB_PROVIDER=package     \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
        -DCMAKE_BUILD_TYPE=Release &&    \
    make VERBOSE=1 -j && \
    make install
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

# Check the occlum libc type and decide the compiler
PKGCONFIGPATH="/opt/occlum/toolchains/gcc/x86_64-linux-gnu/lib/pkgconfig"
OCCLUMINSTALLDIR="/usr/local/occlum/x86_64-linux-gnu"
INSTALLDIR="/usr"
OCCLUMCC="gcc -fPIC -pie"
OCCLUMCXX="g++ -fPIC -pie"
if [ "$1" == "--libc" ] ; then
    if [ "$2" == "musl" ] ; then
        echo "Build with musl libc ..."
        INC_DIR_MUSL="/opt/occlum/toolchains/gcc/x86_64-linux-musl/include"
        PKGCONFIGPATH="/opt/occlum/toolchains/gcc/x86_64-linux-musl/lib/pkgconfig"
        OCCLUMINSTALLDIR="/usr/local/occlum/x86_64-linux-musl"
        INSTALLDIR="/usr/local/occlum/x86_64-linux-musl"
        OCCLUMCC="/usr/local/occlum/bin/occlum-gcc -I$INC_DIR_MUSL"
        OCCLUMCXX="/usr/local/occlum/bin/occlum-g++ -I$INC_DIR_MUSL"
    fi
    shift 2
fi
export CC=$OCCLUMCC
export CXX=$OCCLUMCXX
export PATH=$INSTALLDIR/bin:$PATH
export PKG_CONFIG_LIBDIR=$INSTALLDIR/lib:$PKG_CONFIG_LIBDIR
export PKG_CONFIG_PATH=$PKGCONFIGPATH:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=$INSTALLDIR/lib:$INSTALLDIR/lib64:$LD_LIBRARY_PATH

# Build specified component or all by default
BUILD_COMPONENTS="${1:-$ALL_COMPONENTS}"

# Download all components once here together
mkdir -p $DEPSDIR && cd $DEPSDIR || exit 1
TRYGET $OPENSSLDIR https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1k.tar.gz
TRYGET $CURLDIR https://github.com/curl/curl/archive/curl-7_70_0.tar.gz
#TRYGET $PROTOBUFDIR https://github.com/protocolbuffers/protobuf/releases/download/v21.6/protobuf-all-21.6.tar.gz
#TRYGET $CARESDIR https://c-ares.haxx.se/download/c-ares-1.14.0.tar.gz
#TRYGET $GRPCDIR https://github.com/grpc/grpc/archive/refs/tags/v1.24.3.tar.gz grpc-1.24.3.tar.gz
GITGET_GRPC

for i in $BUILD_COMPONENTS ; do
    if [ "$BUILDFORCE" == "NO" ] ; then
        ${i}_check && LOG_INFO "[READY] build check for $i" && continue
    fi
    LOG_DEBUG "Building $i ..." && ${i}_build && \
    LOG_DEBUG "Build $i successfully" || ERROR_EXIT "Fail to build $i"
done
