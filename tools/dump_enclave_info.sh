#!/usr/bin/env bash

if [ -z "$1" ] ; then
    echo "Usage: $0 enclave.signed.so"
    exit 1
fi

enclave=$1
tmpprefix="/tmp/$(basename $enclave)"
dumpfile="${tmpprefix}.dump"
mrenclavefile="${tmpprefix}.mrenclave"
mrsignerfile="${tmpprefix}.mrsigner"
sgxsign="/opt/intel/sgxsdk/bin/x64/sgx_sign"

rm -rf $dumpfile
$sgxsign dump -enclave $enclave -dumpfile $dumpfile >/dev/null 2>&1
[ "$?" -eq 0 ] || exit 1

rm -rf $mrsignerfile
mrsignerstr=""
echo -e -n "Enclave mrsigner   hexstr: "
for i in $(grep -A 2 "mrsigner->value:" $dumpfile | tail -2 | xargs | sed 's/0x//g' | tr 'a-z' 'A-Z') ; do
    mrsignerstr="${mrsignerstr}${i}"
    echo -e -n $i
    echo $i | xxd -r -ps >> $mrsignerfile
done
echo ""
echo -e -n "Enclave mrsigner   base64: "
base64 -w 0 $mrsignerfile
echo ""
echo "Enclave mrsigner  hexhash: $(echo -n $mrsignerstr | sha256sum | sed 's/\ \ -//g' | tr 'a-z' 'A-Z')"

rm -rf $mrenclavefile
mrenclavestr=""
echo -e -n "Enclave mrenclave  hexstr: "
for i in $(grep -A 2 "enclave_hash.m:" $dumpfile | tail -2 | xargs | sed 's/0x//g' | tr 'a-z' 'A-Z') ; do
    mrenclavestr="${mrenclavestr}${i}"
    echo -e -n $i
    echo $i | xxd -r -ps >> $mrenclavefile
done
echo ""
echo -e -n "Enclave mrenclave  base64: "
base64 -w 0 $mrenclavefile
echo ""
echo "Enclave mrenclave hexhash: $(echo -n $mrenclavestr | sha256sum | sed 's/\ \ -//g' | tr 'a-z' 'A-Z') "

rm -rf $dumpfile $mrenclavefile $mrsignerfile
