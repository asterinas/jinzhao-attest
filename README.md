# Jinzhao Attest

Jinzhao Attest provides unified attestation workflows for TEE compatibility, usability, and security.


# Features Overview

1. Implement the abstraction and interconnection of heterogeneous TEE based on the following conceptions:
  - **UAI**: unified attestation interfaces to generate and verify attestation report
  - **UAR**: unified attestation report in an abstract format for all supported TEE platforms
  - **UAP**: unified attestation policy to verify UAR based on the union set of different TEE attributes.

2. Provide flexible usages for different scenarios:
  - [SGX SDK](https://github.com/intel/linux-sgx) or [Occlum LibOS](https://github.com/occlum/occlum) development model
  - Report verification in the trusted or untrusted environment
  - Report verification by local unified attestation library (**UAL**) or centralized unified attestation service (**UAS**)

```
              .----------------------------.
        .---->| Unified Attestation Report +----.
        |     '----------------------------'    |
        | Unified Attestation Interface         | Unified Attestation Interface
        | (Report Generation)                   | (Report Verification)
        |                                       v
.-------+-------.                       .--------------.
| TEE Platforms |                       |   Verifier   |
'-------+-------'                       '--------------'
        |                                       ^
        |                                       |
        |     .----------------------------.    |
        '---->| Unified Attestation Policy +----'
              '----------------------------'
```

# Supported TEE platforms and interfaces

The following table shows all the TEE platforms we currently support, and the supported interfaces for each TEE platform.

| TEE platforms            | UAR Generation | UAR Verification |
| ------------------------ | -------------- | ---------------- |
| Intel SGX1               | Yes            | Yes              |
| Intel SGX2               | Yes            | Yes              |
| HyperEnclave             | Yes            | Yes              |
| Kunpeng Trustzone        | No             | Yes              |
| Hygon CSV                | Yes            | Yes              |
| Intel TDX                | Yes            | Yes              |


# Quick Start

## Update the submodules

```
git submodule update --init --recursive
```

## Initialize and enter the development environment container

```
./dockerenv.sh --init  # create the container instance

./dockerenv.sh --exec  # enter the container instance
```

## Build the unified attestation library and samples

In the development environment container, run the following command:

```
./build.sh --with-samples --mode SIM
```

NOTE: SIM mode is used here, which means you can try the quick start
in the environment without TEE. If you want to try it in real TEE,
you need to setup the TEE and configure remote attestation firstly.
For example, in SGX2 platform, you need to register the platform to PCCS,
and set the PCCS URL in /etc/sgx_default_qcnl.conf and in
/etc/kubetee/unified_attestation.json (or by environment variable UA_ENV_PCCS_URL).
For How to setup the PCCS, please refer to [Intel DCAP document](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs).


## The other build command examples

```
# Occlum LibOS build environment for SGX1/SGX2/HyperEnclave
./dockerenv.sh --init --occlum
./dockerenv.sh --exec --occlum
./build.sh --with-samples --envtype OCCLUM

# Ubuntu build environment for Hygon CSV or Intel TDX VM TEE
./dockerenv.sh --init --ubuntu --csv|--tdx
./dockerenv.sh --exec --ubuntu --csv|--tdx
./build.sh --with-samples --envtype VMTEE --teetype CSV|TDX
```

## Run the sample code

In the development environment container, run any application samples,
for example, report generation sample like this:

```
mkdir /etc/kubetee
cp ./deployment/conf/unified_attestation.json /etc/kubetee/
cd build/out
./app-sample-unified-attestation-generation
./app-sample-unified-attestation-verification-untrusted
```

NOTE： If the sample applications are built with OCCLUM envtype (which is the default in Occlum docker images),
you need to run the applications in Occlum runtime, please see also "tools/occlum_run_samples.sh".
If you still want to run sample applications in build/out, please specify "--envtype SGXSDK" for SGX TEE.


# Use UAL in your application

Jinzhao Attest provides UAL which can be integrated into an application with SGX SDK, Occlum LibOS, or without TEE at all.

## Include header files

Please choose C++ or C ABI header files according to your programming language.

Header files for C++ programming language: have almost all the public interfaces

  - [ua_untrusted.h](ual/include/unified_attestation/ua_untrusted.h): includes all untrusted header files, used in untrusted code or Occlum application
  - [ua_trusted.h](ual/include/unified_attestation/ua_trusted.h): includes all trusted header files, used in trusted code

Header files for other programming languages which are compatible with C ABI: have limited public interfaces

  - [unified_attestation_generation.h](ual/include/attestation/generation/unified_attestation_generation.h): for calling the generation interface in all cases
  - [unified_attestation_verification.h](ual/include/attestation/verification/unified_attestation_verification.h): for calling the verification interface in all cases

## Include EDL file

This step is only for SGX-liked TEE platforms and SGX-SDK development model

  - [attestation.edl](ual/enclave/edl/attestation.edl): should be included in the trust application top EDL file

## Link unified attestation libraries

In different TEE platforms and different development containers(see also [dockerenv.sh](dockerenv.sh)), you will build out different libraries:

+ Untrusted/Trusted libraries for SGX-liked TEE platforms using SGX-SDK:
  - libual_u.so: untrusted library with generation and verification interfaces
  - libual_t.a: trusted library with generation and verification interfaces
  - libual.so: includes verification interface only and can be used without trusted code.
+ Library for trusted application based on Occlum LibOS:
  - libual.so: includes both generation and verification interfaces.
+ Library for platforms there is no TEE:
  - libual.so: includes verification interface only (Cannot generate UAR without TEE)

NOTES: Please refer to the example applications in the ./samples directory for more details.


# Contributing

Anyone is welcome to provide any form of contribution, for example:

- More TEE platforms (APIs, report format and attributes for different TEE)
- More workflow about TEE based on remote attestation
- More usage scenarios
- Documentation, bug fixes, security improvements
- Others ...

Please check [CONTRIBUTING.md](CONTRIBUTING.md).


# License

Please check [LICENSE](LICENSE) for details.
