# Context-based Authentication (CBA)

This Trusted Application provides a CBA service which authenticates a device based on its WiFi context (derived from measured CSI data).

## General Idea

The service takes a measurement of the device's WiFi context and (at first use) enrolls a context fingerprint at the remote server. Later, another measurement can be taken and compared with the enrolled fingerprint. If it matches, the authentication succeeds, else it fails.

Authentication works as follows: Device A sends a nonce to device B, which sends a measurement and the nonce to the server. If the measurement matches the enrolled fingerprint, the server signs the nonce and returns it to device B, which can (in turn) forward it to A. A verifies the signature, thus knowing that the server validated B's WiFi context.

The communication between the TA and the remote server is secured using mTLS. The client certificate is enrolled with the remote server before the first CSI data exchange takes place. Afterwards, the CN is used to identify the client device in each request.

## Configuration

The following options require configuration in the listed files (the options are located at the top):

| file | option |
| --- | --- |
| `ta/network_handling.c` | remote server host |
|  | remote server port |
|  | remote server TLS certificate |
| `ta/signature_handling.c` | remote server signature certificate |
| `ta/cba.c` | WiFi channel (depends on access point) |
| | WiFi channel bandwidth (20/40/80 MHz; depends on access point) |
| | CSI recording timeout |
| | CSI samples per device (depends on ML model) |


## Build & Installation

This TA requires running on the CROSSCON HV next to a Linux VM which contains a WiFi driver in order to collect the CSI samples. Furthermore, for communicating with this VM, a modified version of OPTEE-OS is required which includes a specific Pseudo TA (see [here](https://github.com/crosscon/context-based-auth-optee-os)). The remote side which validates the measurement is implemented [here](https://github.com/crosscon/context-based-auth-remote).

Building this TA works similar to building other TAs for OPTEE-OS on CROSSCON and depends on the exact build system used. [These instructions (step 6)](https://github.com/crosscon/CROSSCON-Hypervisor-and-TEE-Isolation-Demos/) can generally be used as guidance.

After compilation, the signed TA application `.ta` file must be stored on the Linux file system which invokes the TA execution at `/usr/lib/optee_armtz`. This again depends on the build system used. In the CROSSCON demo repository (which uses buildroot), the developers move the TA and the host application using overlays (see there for further details).


## Usage

An example host application for how to call the TA can be found in the `host` directory for guidance. The TA command IDs are stored in the TA's header file which is located in `ta/include`.

The following commands are available:

### GET_NONCE
- description: returns a random 16 byte nonce (using the TEE random function)
- params:
    - MEMREF_OUTPUT (where retrieved ID will be returned; must be 16 bytes in length)
    - NONE/NONE/NONE
- return value: TEE_SUCCESS on nonce retrieval (nonce found in first parameter)

### ENROLL
- description: enrolls the client certificate & the context fingerprint with the remote server; as this is a "proof of concept", no device validation is performed
- params: NONE/NONE/NONE/NONE
- return value: TEE_SUCCESS on successful enrollment, TEE_ERROR_EXTERNAL_CANCEL on server abort (e.g. already enrolled or other errors)

### PROVE
- description: Takes a measurement and tries to send it to the server for attestation; if remote is unreachable, puts it in the queue
- params:
    - MEMREF_INPUT (16 byte nonce)
    - MEMREF_OUTPUT (signature returned by the server)
    - NONE/NONE
- return value: TEE_SUCCESS on successful proof creation, TEE_ERROR_EXTERNAL_CANCEL on server abort (i.e. comparison failed)

### VERIFY
- description: verifies a given signature for a given nonce using the server signature certificate
- params:
    - MEMREF_INPUT (16 byte nonce)
    - MEMREF_INPUT (signature from the server)
    - NONE/NONE
- return value: TEE_SUCCESS on successful verification, TEE_ERROR_EXTERNAL_CANCEL on failed verification

