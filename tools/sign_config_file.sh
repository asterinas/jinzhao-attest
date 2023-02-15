#!/usr/bin/env bash
#
# This tool is to sign the hash of unified attestation configuration file.
# The output file looks like this:
#   {
#     "configurations_is_signed": "true",
#     "configurations": "ewogIdmbGUuYWxpcGF5Lm5ldDo4MCIsCiAgI....",
#     "hash": "f88e926d226d8454d9bd0764b36557b6490ce0b15730944096d9f76e4e07c049",
#     "signature": "d49E7REN72yOU5hOvQFU+gYl1rhXhw2HOAQ7HMGtU..."
#   }
#
#  For debug mode, we sign configuration file with the local Intel demo key.
#  For release mode, we should sign configuration file with formal signing key.

THISDIR="$(dirname $(readlink -f $0))"
TOPDIR="$(readlink -f $THISDIR/..)"

# Provide some default value before parsing command line
SIGNMODE=${CONFIG_SIGN_MODE:-"local"}

# Define the error exit function
EXIT_ERROR() {
  echo "$@" >&2 ; exit 1
}

# Define the help menu
SHOW_MORE_HELP() {
  cat << EOF
Usage: $0 [options]
Options:
   -key             Specify the signing private key file
   -input           Specify the input file to be signed
   -output          Specify the output file name which is signed.
                    The default filename is <input>.singed
EOF
}

while [ -n "$1" ] ; do
  case "$1" in
    -key)                   PRIVATEKEY=$2 ;          shift 2 ;;
    -input)                 INPUTFILE=$2 ;           shift 2 ;;
    -output)                OUTPUTFILE=$2 ;          shift 2 ;;
    -h|-help|--help)        SHOW_MORE_HELP ;         exit 0  ;;
    *)   EXIT_ERROR "Invalid options for sign subcommand: $1" ;;
  esac
done

# Check the input file
[ -f "$INPUTFILE" ] || EXIT_ERROR "Invalid input file $INPUTFILE"

# Get output file name from intput file name, and check output filename
[ -n "$OUTPUTFILE" ] || OUTPUTFILE=${INPUTFILE}.signed
OUTDIR="$(dirname $OUTPUTFILE)"
mkdir -p "$OUTDIR" || EXIT_ERROR "Invalid output directory: $OUTDIR"
touch $OUTPUTFILE || EXIT_ERROR "Cannot write output file $OUTPUTFILE"

###############################################################
# STEP1: Generate the configuration file section
###############################################################
OUTPUT_CONFIGURATIONS="$(base64 $INPUTFILE --wrap=0)"

###############################################################
# STEP2: Generate the hash of configuration section
###############################################################
OUTPUT_HASH="$(sha256sum $INPUTFILE --binary | awk '{print $1}' | tr 'a-z' 'A-Z')"

###############################################################
# STEP3: Generate the signature of hash in **STRING** format
###############################################################
echo "Signing mode: $SIGNMODE"
HASHFILE="${INPUTFILE}.hash"
SIGNATUREFILE="${HASHFILE}.sig"
echo -ne ${OUTPUT_HASH} > $HASHFILE

# Check the input parameters for local signing
[ -f "$PRIVATEKEY" ] || EXIT_ERROR "Invalid private key file $PRIVATEKEY"

openssl dgst -sha256 -out $SIGNATUREFILE \
    -sign $PRIVATEKEY -keyform PEM $HASHFILE && \
ret=$?

# Save all temprary things into variables
OUTPUT_SIGNATURE="$(base64 $SIGNATUREFILE --wrap=0)"

# Do some cleanup, remove all temprary files
rm -rf $HASHFILE $SIGNATUREFILE

###############################################################
# STEP4: Output all to the file
###############################################################
if [ "$ret" != "0" ] ; then
  EXIT_ERROR "Fail to sign the configuration file!"
fi

cat << EOF > $OUTPUTFILE
{
  "configurations_is_signed": "true",
  "configurations": "$OUTPUT_CONFIGURATIONS",
  "hash": "$OUTPUT_HASH",
  "signature": "$OUTPUT_SIGNATURE"
}
EOF

echo "Finished, output file here: $OUTPUTFILE"
exit 0
