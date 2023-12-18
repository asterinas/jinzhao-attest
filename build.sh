#!/usr/bin/env bash

THISDIR="$(readlink -f $(dirname $0))"

OPT_BUILD_MODE=Debug
OPT_VERBOSE=0
OPT_INSTALL=0
OPT_MAKE_INSTALL=0
OPT_SGX_MODE=""
OPT_TEE_TYPE=""
OPT_ENV_TYPE=""
OPT_LOG_LEVEL="INFO"
OPT_WITH_SAMPLES="OFF"
OPT_WITH_UAS_APP="OFF"
OPT_WITH_SM="OFF"
OPT_OCCLUM_LIBC="gnu"

# For static build, need this option to build static library
# and also set(CMAKE_EXE_LINKER_FLAGS "-static") and add -ldl for static link
# The static version of other dependent libraries alos must exist.
# For example, nedd static libstdc++, libc:
#   yum install -b current libstdc++-static
#   yum install -b current glibc-static
# Other static libraries for ual: (occlum prepared the following two)
#   libcrypto.a
#   libssl.a
#   libcurl.a (need libcrypto.a from openssl with enable-egd)
#   libprotobuf.a
OPT_WITH_STATIC="OFF"

# Link all sources into a shared library libual_u.so/libual_t.a
OPT_MERGED_LIBS="ON"

EXIT_ERROR() {
    echo "$@" >&2
    exit 1
}

get_tee_environment() {
    if [ -e "/dev/jailhouse" -o -e "/dev/hyperenclave" ] ; then
        echo -ne "HYPERENCLAVE"
    elif [ -e "/dev/sgx_enclave" -o -e "/dev/sgx/enclave" ] ; then
        echo -ne "SGX2"
    elif [ -e "/dev/isgx" ] ; then
        echo -ne "SGX1"
    else
        echo -ne "NONE"
    fi
}

get_programming_environment() {
    if [ -e "/opt/occlum/build/bin/occlum" ] ; then
        echo -ne "OCCLUM"
    elif [ -e "/opt/intel/sgxsdk/environment" ] ; then
        echo -ne "SGXSDK"
    else
        echo -ne "LINUX"
    fi
}

do_clean() {
    echo "remove ./build ..."
    rm -rf ./build
}

do_compile() {
    local has_tee="ON"
    local build_samples="OFF"
    local verbose_opt=""
    local tee_opt=""
    local env_opt=""

    [ -z "$OPT_TEE_TYPE" -a "$OPT_SGX_MODE" == "SIM" ] && OPT_TEE_TYPE="SGX1"
    [ -z "$OPT_TEE_TYPE" ] && OPT_TEE_TYPE=$(get_tee_environment)
    [ -z "$OPT_ENV_TYPE" ] && OPT_ENV_TYPE=$(get_programming_environment)
    echo "Build in TEE environment: ${OPT_TEE_TYPE}"
    echo "Build in Programming environment: ${OPT_ENV_TYPE}"

    if [ -z "$OPT_SGX_MODE" ] ; then
        if [ "$OPT_TEE_TYPE" == "HYPERENCLAVE" ] ; then
            OPT_SGX_MODE="HYPER"
        else
            OPT_SGX_MODE="HW"
        fi
    fi

    if [ "$OPT_SGX_MODE" == "HYPER" ] ; then
        export SGX_SIGN_SIGNTOOL="/opt/intel/sgxsdk/bin/x64/sgx_sign_hyper"
    else
        export SGX_SIGN_SIGNTOOL="/opt/intel/sgxsdk/bin/x64/sgx_sign"
    fi

    [ "$OPT_VERBOSE" -eq 1 ] && verbose_opt="VERBOSE=1"

    # If there is TEE hardware, set a build flag for this case
    # But for occlum, we deal with it like normal no-tee envrionment.
    [ "$OPT_TEE_TYPE" == "NONE" ] && has_tee="OFF"
    [ "$OPT_ENV_TYPE" == "OCCLUM" ] && has_tee="OFF"
    [ "$OPT_ENV_TYPE" == "VMTEE" ] && has_tee="OFF"

    # Need to prepare the occlum dependencies
    if [ "$OPT_ENV_TYPE" == "OCCLUM" ] ; then
        [ "$OPT_OCCLUM_LIBC" == "glibc" ] && OPT_OCCLUM_LIBC="gnu"
        $THISDIR/tools/occlum_build_prepare.sh --libc $OPT_OCCLUM_LIBC || exit 1
        if [ "$OPT_OCCLUM_LIBC" == "musl" ] ; then
            export CC="/usr/local/occlum/bin/occlum-gcc"
            export CXX="/usr/local/occlum/bin/occlum-g++"
        else
            export CC="gcc -fPIC -pie"
            export CXX="g++ -fPIC -pie"
        fi
    fi

    if [ "$OPT_WITH_STATIC" == "ON" ] ; then
        $THISDIR/tools/static_build_prepare.sh || exit 1
    fi

    rm -rf $THISDIR/build/out/*.so
    rm -rf $THISDIR/build/out/*.a
    mkdir -p $THISDIR/build && cd $THISDIR/build && \
    cmake -DHAS_TEE=${has_tee} \
          -DSGX_MODE=${OPT_SGX_MODE} \
          -DTEE_TYPE=${OPT_TEE_TYPE} \
          -DENV_TYPE=${OPT_ENV_TYPE} \
          -DBUILD_MODE=${OPT_BUILD_MODE} \
          -DLOG_LEVEL=${OPT_LOG_LEVEL} \
          -DBUILD_SAMPLES=${OPT_WITH_SAMPLES} \
          -DBUILD_UAS_APP=${OPT_WITH_UAS_APP} \
          -DBUILD_STATIC=${OPT_WITH_STATIC} \
          -DBUILD_MERGED_LIBS=${OPT_MERGED_LIBS} \
          -DBUILD_SM=${OPT_WITH_SM} \
          -DOCCLUM_LIBC=${OPT_OCCLUM_LIBC} \
          ../ && \
    make $verbose_opt -j$(nproc)
}

do_update() {
    if [ ! -d third_party/protobuf-cpp ] ; then
        git submodule update --init --recursive
    fi
}

do_install_all() {
    local installdir="/opt/kubetee/unified-attestation"

    # The remove action is secure only when
    # we used a independent ua install directory
    rm -rf $installdir
    mkdir -p $installdir/edl
    mkdir -p $installdir/include
    mkdir -p $installdir/lib64
    mkdir -p $installdir/config

    # include/google has cc file
    # cp -Lr $THISDIR/ual/include/*  $installdir/include/
    do_install_cmake
    echo "== Installing all files to $installdir"
    cp -r $THISDIR/build/install/include/* $installdir/include/
    cp -r $THISDIR/ual/proto/*.proto $installdir/include/
    cp -r $THISDIR/ual/enclave/edl/*.edl  $installdir/edl/
    cp -r $THISDIR/deployment/conf/*.json $installdir/config/

    cp -r $THISDIR/build/attestation.pb.* $installdir/include/
}

do_install_cmake() {
    cd $THISDIR/build && rm -rf $THISDIR/build/install
	  make install
}

show_help() {
    cat <<EOF
Usage: ${0} [options]

Options:
    --build         Specify the build types in Debug|PreRelease|Release
                    The default build type is ${OPT_BUILD_MODE}
    --mode          Specify the SGX mode in SIM/HW/HYPER, default mode is ${OPT_SGX_MODE}
    --teetype       Specify the TEE platform(SGX1/SGX2/HYPERENCLAVE/NONE)
    --envtype       Specify the programming environment(SGXSDK/OCCLUM/LINUX), SGXSDK as default
    --clean         Clean all build stuffs
    --update        Update code before build
    --log           Log level, [OFF/DEBUG] INFO as default, OFF to disable all log messages
    --with-samples  Build the samples code
    --occlum-musl   Using musl c library in the occlum environment
    --static        Build static libraries instead of shared libraries
    --merged        Build all UAL source files into all-in-one library, ON|OFF.
    --sm            Build the sm algorithm
    -v              Show gcc command in detail when build
    -h|--help       Show this help menu
EOF
}

ARGS=`getopt -o vh -l help,clean,update,build:,teetype:,envtype:,install,make-install,mode:,log:,with-samples,occlum-musl,sm,static,merged: -- "$@"`
[ $? != 0 ] && EXIT_ERROR "Invalid Arguments ..."
eval set -- "$ARGS"
while true ; do
    case "$1" in
        --build)        OPT_BUILD_MODE="$2" ;   shift 2 ;;
        --mode)         OPT_SGX_MODE="$2" ;     shift 2 ;;
        --teetype)      OPT_TEE_TYPE="$2" ;     shift 2 ;;
        --envtype)      OPT_ENV_TYPE="$2" ;     shift 2 ;;
        --log)          OPT_LOG_LEVEL="$2" ;    shift 2 ;;
        --merged)       OPT_MERGED_LIBS="$2" ;  shift 2 ;;
        --install)      OPT_INSTALL=1 ;         shift 1 ;;
        --make-install) OPT_MAKE_INSTALL=1 ;    shift 1 ;;
        --clean)        OPT_DO_CLEAN=1 ;        shift 1 ;;
        --update)       OPT_DO_UPDATE=1 ;       shift 1 ;;
        --with-samples) OPT_WITH_SAMPLES="ON" ; shift 1 ;;
        --sm)           OPT_WITH_SM="ON" ;      shift 1 ;;
        --static)       OPT_WITH_STATIC="ON" ;  shift 1 ;;
        --occlum-musl)  OPT_OCCLUM_LIBC="musl" ; shift 1 ;;
        -v)             OPT_VERBOSE=1 ;         shift 1 ;;
        -h|--help)      show_help ; exit 0 ;;
        --)             shift ; break ;;
        *)              EXIT_ERROR "Args parser internal error!" ;;
    esac
done

find $THISDIR -wholename "ual/external/protobuf-cpp/src" || \
EXIT_ERROR "Please try again after 'git submodule update --init --recursive'"

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib:/usr/local/lib:/usr/lib64

cd $THISDIR
if [ "$OPT_DO_CLEAN" == 1 ] ; then
    do_clean
elif [ "$OPT_DO_UPDATE" == 1 ] ; then
    do_update
elif [ "$OPT_INSTALL" == 1 ] ; then
    do_install_all
elif [ "$OPT_MAKE_INSTALL" == 1 ] ; then
    do_install_cmake
else
    do_compile
fi
exit $?
