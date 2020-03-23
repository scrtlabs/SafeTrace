# Intel SGX

Intel SGX, a type of Trusted Execution Environment (TEE), is a region of hardware-protected memory inside a computer, where code and data are located that cannot be read or saved by any process outside this private region (called an "enclave"). Enclaves have their own private and public keypair, and the private key is not known outside of the enclave. A process known as "remote attestation" provides many guarantees around the correct functioning of an enclave. For more information, see Intel's [developer documentation](https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf)

# Intel Remote Attestation

Remote attestation, an advanced feature of Intel SGX, is the process of proving that an enclave
has been established in a secure hardware environment. This means that a remote party can
verify that the right application is running inside an enclave on an Intel SGX enabled platform.
Remote attestation provides verification for three things: the application’s identity, its
intactness (that it has not been tampered with), and that it is running securely within an enclave
on an Intel SGX enabled platform. Attestation is necessary in order to make remote access
secure, since very often the enclave’s contents may have to be accessed remotely, not from the
same platform [[1]]

The attestation process consists of seven stages, encompassing several actors, namely the
service provider (referred to as a challenger) on one platform; and the application, the application’s enclave, the Intel-provided Quoting Enclave (QE) and Provisioning Enclave (PvE) on another platform. A separate entity in the attestation process is Intel Attestation Service (IAS), which carries out the verification of the enclave [[1]][[2]][[3]].

In short, the seven stages of remote attestation comprise of making a remote attestation request
(stage 1), performing a local attestation (stages 2-3), converting the local attestation to a remote
attestation (stages 4-5), returning the remote attestation to the challenger (stage 6) and verifying
the remote attestation (stage 7) [[1]][[3]].

Intel Remote Attestation also includes the establishment of a secure communication session between the service provider and the application. This is analogous to how the familiar SSL handshake includes both authentication and session establishment. 