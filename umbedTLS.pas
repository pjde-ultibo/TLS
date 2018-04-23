unit umbedTLS;

{$mode objfpc}{$H+}

(* Pascal Header Translation of mbedTLS 2018 pjde
*
*
*  mbedTLS
*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*
*  Build instructions for mbed TLS
*
*  Downloaded source from https://tls.mbed.org/download
*  Unzip to folder
*  Edit config.h in \include\mbedtls folder
     uncomment out (line 947) #define MBEDTLS_NO_PLATFORM_ENTROPY
     comment out (line 2175) //#define MBEDTLS_NET_C
     comment out (line 2562) //#define MBEDTLS_TIMING_C
*  Edit dirent.h in the include/sys folder of the arm-none-eabi-gcc compiler
   replace

      #error "<dirent.h> not supported."

   with

      #ifdef _ULTIBO_
      /* Get Ultibo to take care of functions */
      #define NAME_MAX    255

      #define DT_UNKNOWN  0  // unknown type
      #define DT_FIFO     1  // a named pipe, or FIFO
      #define DT_CHR  	  2  // a character device
      #define DT_DIR 		  4  // a directory
      #define DT_BLK 		  6  // a block device
      #define DT_REG 		  8  // regular file
      #define DT_LNK 		  10 // symbolic link
      #define DT_SOCK   	12 // local domain socket
      #define DT_WHT 	  	14 // ?

      typedef struct dirent
      {
        ino_t d_ino;
        off_t d_off;
        short d_reclen;
        unsigned char d_type;
        char d_name[NAME_MAX + 1];
      } dirent;

      typedef struct __DIR
      {  /* This is defined and only used within Ultibo so can be made opaque.  */
      } DIR;

      int            closedir(DIR * );
      DIR           *opendir(const char * );
      struct dirent *readdir(DIR * );
      int            readdir_r(DIR *, struct dirent *, struct dirent ** );
      void           rewinddir(DIR * );
      void           seekdir(DIR *, long int);
      long int       telldir(DIR * );

      #else
      #error "<dirent.h> not supported here."
      #endif

*  Create a subfolder within named "Build".
*  Open comamnd line prompt and change directory to this folder.
*  Compile with "arm-none-eabi-gcc -O2 -mabi=aapcs -marm -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard -D__DYNAMIC_REENT__ -I../include -c ../library/*.c"
*  Create library with "arm-none-eabi-ar rc libmbedtls.a *.o"
*  Copy library to relevant project folder.
*)

interface

uses
  Classes, SysUtils, SysCalls;

{$linklib mbedtls}

const
  MBEDTLS_SSL_VERIFY_DATA_MAX_LEN          = 12;

type
  mbedtls_ssl_states                       = LongWord; // enum
  size_t                                   = integer;  // 4 bytes
  Psize_t                                  = ^size_t;
  uint32_t                                 = LongWord;
  Puint32_t                                = ^uint32_t;
  uint16_t                                 = uint16;
  uint64_t                                 = uint64;

  Pmbedtls_ssl_session                     = ^mbedtls_ssl_session;
  Pmbedtls_ssl_context                     = ^mbedtls_ssl_context;
  Pmbedtls_ssl_config                      = ^mbedtls_ssl_config;
  Pmbedtls_ssl_transform                   = ^mbedtls_ssl_transform;
  Pmbedtls_ssl_handshake_params            = ^mbedtls_ssl_handshake_params;
  Pmbedtls_md_info_t                       = pointer; // opaque
  Pmbedtls_x509_crt                        = ^mbedtls_x509_crt;
  Pmbedtls_x509_crl                        = ^mbedtls_x509_crl;
  Pmbedtls_entropy_context                 = ^mbedtls_entropy_context;
  Pmbedtls_ctr_drbg_context                = ^mbedtls_ctr_drbg_context;
  mbedtls_time_t                           = integer;  // 4 bytes

  TEntropyFunc                             = function (data : pointer; output : PChar; len : size_t) : integer; cdecl;
  PEntropyFunc                             = ^TEntropyFunc;
  TrngFunc                                 = function (data : pointer; output : PChar; len : size_t) : integer; cdecl;
  TdbgFunc                                 = procedure (data : pointer; i : integer; c : PChar; i2 : integer; c2 : PChar); cdecl;
  TNetSendFunc                             = function (ctx : pointer; buf : pointer; len : size_t) : integer; cdecl;
  TNetRecvFunc                             = function (ctx : pointer; buf : pointer; len : size_t) : integer; cdecl;
  TNetRecvTimeoutFunc                      = function (ctx : pointer; buf : pointer; len : size_t; timeout : uint32_t) : integer; cdecl;
  TGetTimerFunc                            = function (ctx : pointer) : integer; cdecl;
  TSetTimerFunc                            = procedure (ctx : pointer; int_ms : uint32_t; fin_ms : uint32_t); cdecl;

  {$PACKRECORDS C}

  //all these records / structures can be made opaque

  mbedtls_x509_crt = record // size 308
    stuffing : array [0 .. 307] of byte;
  end;

   mbedtls_x509_crl = record // size 244
    stuffing : array [0 .. 243] of byte;
  end;

  mbedtls_ctr_drbg_context = record // size 320
    stuffing : array [0 .. 319] of byte;
  end;

  mbedtls_entropy_context = record // size 632
    stuffing : array [0 .. 631] of byte;
  end;

  mbedtls_ssl_session = record  // size 128
    stuffing : array [0 .. 127] of byte;
  end;

  mbedtls_ssl_handshake_params = record // size 2192
    stuffing : array [0 .. 2191] of byte;
  end;

  mbedtls_ssl_transform = record // size 208
    stuffing : array [0 .. 207] of byte;
  end;

  mbedtls_ssl_config = record // size 208
    stuffing : array [0 .. 207] of byte;
  end;

  mbedtls_ssl_context = record // size 264
    stuffing : array [0 .. 263] of byte;
  end;

const
(* SSL Error codes  - actually negative of these *)
  MBEDTLS_ERR_MPI_FILE_IO_ERROR            = $0002;  // An error occurred while reading from or writing to a file.
  MBEDTLS_ERR_MPI_BAD_INPUT_DATA           = $0004;  // Bad input parameters to function.
  MBEDTLS_ERR_MPI_INVALID_CHARACTER        = $0006;  // There is an invalid character in the digit string.
  MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL         = $0008;  // The buffer is too small to write to.
  MBEDTLS_ERR_MPI_NEGATIVE_VALUE           = $000A;  // The input arguments are negative or result in illegal output.
  MBEDTLS_ERR_MPI_DIVISION_BY_ZERO         = $000C;  // The input argument for division is zero, which is not allowed.
  MBEDTLS_ERR_MPI_NOT_ACCEPTABLE           = $000E;  // The input arguments are not acceptable.
  MBEDTLS_ERR_MPI_ALLOC_FAILED             = $0010;  // Memory allocation failed.

  MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG    = $0003;  // Too many random requested in single call.
  MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG      = $0005;  // Input too large (Entropy + additional).
  MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR      = $0007;  // Read/write error in file.
  MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED = $0009;  // The entropy source failed.

  MBEDTLS_ERR_CCM_BAD_INPUT                = $000D; // Bad input parameters to the function.
  MBEDTLS_ERR_CCM_AUTH_FAILED              = $000F; // Authenticated decryption failed.
  MBEDTLS_ERR_CCM_HW_ACCEL_FAILED          = $0011; // CCM hardware accelerator failed.

  MBEDTLS_ERR_GCM_AUTH_FAILED              = $0012;  // Authenticated decryption failed.
  MBEDTLS_ERR_GCM_HW_ACCEL_FAILED          = $0013;  // GCM hardware accelerator failed.
  MBEDTLS_ERR_GCM_BAD_INPUT                = $0014;  // Bad input parameters to function.

  MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH  = $0016;  // Invalid key length.
  MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED     = $0017;  // Blowfish hardware accelerator failed.
  MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH = $0018;  // Invalid data input length.

  MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED         = $0019;  // ARC4 hardware accelerator failed.

  MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE = $001A;  // The selected feature is not available.
  MBEDTLS_ERR_THREADING_BAD_INPUT_DATA     = $001C;  // Bad input parameters to function.
  MBEDTLS_ERR_THREADING_MUTEX_ERROR        = $001E;  // Locking / unlocking / free failed with error code.

  MBEDTLS_ERR_AES_INVALID_KEY_LENGTH       = $0020;  // Invalid key length.
  MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH     = $0022;  // Invalid data input length.

  MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE      = $0023;  // Feature not available. For example, an unsupported AES key size.
  MBEDTLS_ERR_AES_HW_ACCEL_FAILED          = $0025;  // AES hardware accelerator failed.

  MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH  = $0024;  // Invalid key length.
  MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH = $0026;  // Invalid data input length.
  MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED     = $0027;  // Camellia hardware accelerator failed.

  MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH    = $0028;  // The data input has an invalid length.
  MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED         = $0029;  // XTEA hardware accelerator failed.

  MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL      = $002A;  // Output buffer too small.
  MBEDTLS_ERR_BASE64_INVALID_CHARACTER     = $002C;  // Invalid character in input.

  MBEDTLS_ERR_MD2_HW_ACCEL_FAILED          = $002B;  // MD2 hardware accelerator failed
  MBEDTLS_ERR_MD4_HW_ACCEL_FAILED          = $002D;  // MD4 hardware accelerator failed
  MBEDTLS_ERR_MD5_HW_ACCEL_FAILED          = $002F;  // MD5 hardware accelerator failed

  MBEDTLS_ERR_OID_NOT_FOUND                = $002E;  // OID is not found.
  MBEDTLS_ERR_OID_BUF_TOO_SMALL            = $000B;  // output buffer is too small

  MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED      = $0030;  // Input data should be aligned.

  MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED    = $0031;  // RIPEMD160 hardware accelerator failed

  MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH     = $0032;  // The data input has an invalid length.
  MBEDTLS_ERR_DES_HW_ACCEL_FAILED          = $0033;  // DES hardware accelerator failed.

  MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED = $0034;  // The entropy source failed.
  MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG     = $0036;  // The requested random buffer length is too big.
  MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG       = $0038;  // The input (entropy + additional data) is too large.
  MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR       = $003A;  // Read or write error in file.

  MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED         = $0035;  // SHA-1 hardware accelerator failed
  MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED       = $0037;  // SHA-256 hardware accelerator failed
  MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED       = $0039;  // SHA-512 hardware accelerator failed

  MBEDTLS_ERR_ENTROPY_SOURCE_FAILED        = $003C;  // Critical entropy source failure.
  MBEDTLS_ERR_ENTROPY_MAX_SOURCES          = $003E;  // No more sources can be added.
  MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED   = $0040;  // No sources have been added to poll.
  MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE     = $003D;  // No strong sources have been added to poll.
  MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR        = $003F;  // Read/write error in file.

  MBEDTLS_ERR_NET_SOCKET_FAILED            = $0042;  // Failed to open a socket.
  MBEDTLS_ERR_NET_CONNECT_FAILED           = $0044;  // The connection to the given server / port failed.
  MBEDTLS_ERR_NET_BIND_FAILED              = $0046;  // Binding of the socket failed.
  MBEDTLS_ERR_NET_LISTEN_FAILED            = $0048;  // Could not listen on the socket.
  MBEDTLS_ERR_NET_ACCEPT_FAILED            = $004A;  // Could not accept the incoming connection.
  MBEDTLS_ERR_NET_RECV_FAILED              = $004C;  // Reading information from the socket failed.
  MBEDTLS_ERR_NET_SEND_FAILED              = $004E;  // Sending information through the socket failed.
  MBEDTLS_ERR_NET_CONN_RESET               = $0050;  // Connection was reset by peer.
  MBEDTLS_ERR_NET_UNKNOWN_HOST             = $0052;  // Failed to get an IP address for the given hostname.
  MBEDTLS_ERR_NET_BUFFER_TOO_SMALL         = $0043;  // Buffer is too small to hold the data.
  MBEDTLS_ERR_NET_INVALID_CONTEXT          = $0045;  // The context is invalid, eg because it was free()ed.

  MBEDTLS_ERR_ASN1_OUT_OF_DATA             = $0060;  // Out of data when parsing an ASN1 data structure.
  MBEDTLS_ERR_ASN1_UNEXPECTED_TAG          = $0062;  // ASN1 tag was of an unexpected value.
  MBEDTLS_ERR_ASN1_INVALID_LENGTH          = $0064;  // Error when trying to determine the length or invalid length.
  MBEDTLS_ERR_ASN1_LENGTH_MISMATCH         = $0066;  // Actual length differs from expected length.
  MBEDTLS_ERR_ASN1_INVALID_DATA            = $0068;  // Data is invalid. (not used)
  MBEDTLS_ERR_ASN1_ALLOC_FAILED            = $006A;  // Memory allocation failed
  MBEDTLS_ERR_ASN1_BUF_TOO_SMALL           = $006C;  // Buffer too small when writing ASN.1 data structure.

  MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED         = $007A;  // CMAC hardware accelerator failed.

  MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT = $1080;  // No PEM header or footer found.
  MBEDTLS_ERR_PEM_INVALID_DATA             = $1100;  // PEM string is not as expected.
  MBEDTLS_ERR_PEM_ALLOC_FAILED             = $1180;  // Failed to allocate memory.
  MBEDTLS_ERR_PEM_INVALID_ENC_IV           = $1200;  // RSA IV is not in hex-format.
  MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG          = $1280;  // Unsupported key encryption algorithm.
  MBEDTLS_ERR_PEM_PASSWORD_REQUIRED        = $1300;  // Private key password can't be empty.
  MBEDTLS_ERR_PEM_PASSWORD_MISMATCH        = $1380;  // Given private key password does not allow for correct decryption.
  MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE      = $1400;  // Unavailable feature, e.g. hashing/encryption combination.
  MBEDTLS_ERR_PEM_BAD_INPUT_DATA           = $1480;  // Bad input parameters to function.

  MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA        = $1F80;  // Bad input parameters to function.
  MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE   = $1F00;  // Feature not available, e.g. unsupported encryption scheme.
  MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT    = $1E80;  // PBE ASN.1 data not as expected.
  MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH     = $1E00;  // Given private key password does not allow for correct decryption.

  MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE     = $2080;  // Unavailable feature, e.g. RSA hashing/encryption combination.
  MBEDTLS_ERR_X509_UNKNOWN_OID             = $2100;  // Requested OID is unknown.
  MBEDTLS_ERR_X509_INVALID_FORMAT          = $2180;  // The CRT/CRL/CSR format is invalid, e.g. different type expected.
  MBEDTLS_ERR_X509_INVALID_VERSION         = $2200;  // The CRT/CRL/CSR version element is invalid.
  MBEDTLS_ERR_X509_INVALID_SERIAL          = $2280;  // The serial tag or value is invalid.
  MBEDTLS_ERR_X509_INVALID_ALG             = $2300;  // The algorithm tag or value is invalid.
  MBEDTLS_ERR_X509_INVALID_NAME            = $2380;  // The name tag or value is invalid.
  MBEDTLS_ERR_X509_INVALID_DATE            = $2400;  // The date tag or value is invalid.
  MBEDTLS_ERR_X509_INVALID_SIGNATURE       = $2480;  // The signature tag or value invalid.
  MBEDTLS_ERR_X509_INVALID_EXTENSIONS      = $2500;  // The extension tag or value is invalid.
  MBEDTLS_ERR_X509_UNKNOWN_VERSION         = $2580;  // CRT/CRL/CSR has an unsupported version number.
  MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG         = $2600;  // Signature algorithm (oid) is unsupported.
  MBEDTLS_ERR_X509_SIG_MISMATCH            = $2680;  // Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid)
  MBEDTLS_ERR_X509_CERT_VERIFY_FAILED      = $2700;  // Certificate verification failed, e.g. CRL, CA or signature check failed.
  MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT     = $2780;  // Format not recognized as DER or PEM.
  MBEDTLS_ERR_X509_BAD_INPUT_DATA          = $2800;  // Input invalid.
  MBEDTLS_ERR_X509_ALLOC_FAILED            = $2880;  // Allocation of memory failed.
  MBEDTLS_ERR_X509_FILE_IO_ERROR           = $2900;  // Read/write of file failed.
  MBEDTLS_ERR_X509_BUFFER_TOO_SMALL        = $2980;  // Destination buffer is too small.
  MBEDTLS_ERR_X509_FATAL_ERROR             = $3000;  // A fatal error occured, eg the chain is too long or the vrfy callback failed.

  MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA         = $2F80;  // Bad input parameters to function.
  MBEDTLS_ERR_PKCS5_INVALID_FORMAT         = $2F00;  // Unexpected ASN.1 data.
  MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE    = $2E80;  // Requested encryption or digest alg not available.
  MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH      = $2E00;  // Given private key password does not allow for correct decryption.

  MBEDTLS_ERR_DHM_BAD_INPUT_DATA           = $3080;  // Bad input parameters.
  MBEDTLS_ERR_DHM_READ_PARAMS_FAILED       = $3100;  // Reading of the DHM parameters failed.
  MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED       = $3180;  // Making of the DHM parameters failed.
  MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED       = $3200;  // Reading of the public values failed.
  MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED       = $3280;  // Making of the public value failed.
  MBEDTLS_ERR_DHM_CALC_SECRET_FAILED       = $3300;  // Calculation of the DHM secret failed.
  MBEDTLS_ERR_DHM_INVALID_FORMAT           = $3380;  // The ASN.1 data is not formatted correctly.
  MBEDTLS_ERR_DHM_ALLOC_FAILED             = $3400;  // Allocation of memory failed.
  MBEDTLS_ERR_DHM_FILE_IO_ERROR            = $3480;  // Read or write of file failed.
  MBEDTLS_ERR_DHM_HW_ACCEL_FAILED          = $3500;  // DHM hardware accelerator failed.
  MBEDTLS_ERR_DHM_SET_GROUP_FAILED         = $3580;  // Setting the modulus and generator failed.

  MBEDTLS_ERR_PK_ALLOC_FAILED              = $3F80;  // Memory allocation failed.
  MBEDTLS_ERR_PK_TYPE_MISMATCH             = $3F00;  // Type mismatch, eg attempt to encrypt with an ECDSA key
  MBEDTLS_ERR_PK_BAD_INPUT_DATA            = $3E80;  // Bad input parameters to function.
  MBEDTLS_ERR_PK_FILE_IO_ERROR             = $3E00;  // Read/write of file failed.
  MBEDTLS_ERR_PK_KEY_INVALID_VERSION       = $3D80;  // Unsupported key version
  MBEDTLS_ERR_PK_KEY_INVALID_FORMAT        = $3D00;  // Invalid key tag or value.
  MBEDTLS_ERR_PK_UNKNOWN_PK_ALG            = $3C80;  // Key algorithm is unsupported (only RSA and EC are supported).
  MBEDTLS_ERR_PK_PASSWORD_REQUIRED         = $3C00;  // Private key password can't be empty.
  MBEDTLS_ERR_PK_PASSWORD_MISMATCH         = $3B80;  // Given private key password does not allow for correct decryption.
  MBEDTLS_ERR_PK_INVALID_PUBKEY            = $3B00;  // The pubkey tag or value is invalid (only RSA and EC are supported).
  MBEDTLS_ERR_PK_INVALID_ALG               = $3A80;  // The algorithm tag or value is invalid.
  MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE       = $3A00;  // Elliptic curve is unsupported (only NIST curves are supported).
  MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE       = $3980;  // Unavailable feature, e.g. RSA disabled for RSA key.
  MBEDTLS_ERR_PK_SIG_LEN_MISMATCH          = $3900;  // The signature is valid but its length is less than expected.
  MBEDTLS_ERR_PK_HW_ACCEL_FAILED           = $3880;  // PK hardware accelerator failed.

  MBEDTLS_ERR_RSA_BAD_INPUT_DATA           = $4080;  // Bad input parameters to function.
  MBEDTLS_ERR_RSA_INVALID_PADDING          = $4100;  // Input data contains invalid padding and is rejected.
  MBEDTLS_ERR_RSA_KEY_GEN_FAILED           = $4180;  // Something failed during generation of a key.
  MBEDTLS_ERR_RSA_KEY_CHECK_FAILED         = $4200;  // Key failed to pass the validity check of the library.
  MBEDTLS_ERR_RSA_PUBLIC_FAILED            = $4280;  // The public key operation failed.
  MBEDTLS_ERR_RSA_PRIVATE_FAILED           = $4300;  // The private key operation failed.
  MBEDTLS_ERR_RSA_VERIFY_FAILED            = $4380;  // The PKCS#1 verification failed.
  MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE         = $4400;  // The output buffer for decryption is not large enough.
  MBEDTLS_ERR_RSA_RNG_FAILED               = $4480;  // The random generator failed to generate non-zeros.
  MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION    = $4500;  // The implementation does not offer the requested operation, for example, because of security violations or lack of functionality.
  MBEDTLS_ERR_RSA_HW_ACCEL_FAILED          = $4580;  // RSA hardware accelerator failed.

  MBEDTLS_ERR_ECP_BAD_INPUT_DATA           = $4F80;  // Bad input parameters to function.
  MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL         = $4F00;  // The buffer is too small to write to.
  MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE      = $4E80;  // Requested curve not available.
  MBEDTLS_ERR_ECP_VERIFY_FAILED            = $4E00;  // The signature is not valid.
  MBEDTLS_ERR_ECP_ALLOC_FAILED             = $4D80;  // Memory allocation failed.
  MBEDTLS_ERR_ECP_RANDOM_FAILED            = $4D00;  // Generation of random value, such as (ephemeral) key, failed.
  MBEDTLS_ERR_ECP_INVALID_KEY              = $4C80;  // Invalid private or public key.
  MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH         = $4C00;  // Signature is valid but shorter than the user-supplied length.
  MBEDTLS_ERR_ECP_HW_ACCEL_FAILED          = $4B80;  // ECP hardware accelerator failed.

  MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE       = $5080;  // The selected feature is not available.
  MBEDTLS_ERR_MD_BAD_INPUT_DATA            = $5100;  // Bad input parameters to function.
  MBEDTLS_ERR_MD_ALLOC_FAILED              = $5180;  // Failed to allocate memory.
  MBEDTLS_ERR_MD_FILE_IO_ERROR             = $5200;  // Opening or reading of file failed.
  MBEDTLS_ERR_MD_HW_ACCEL_FAILED           = $5280;  // MD hardware accelerator failed.

  MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE   = $6080;  // The selected feature is not available.
  MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA        = $6100;  // Bad input parameters.
  MBEDTLS_ERR_CIPHER_ALLOC_FAILED          = $6180;  // Failed to allocate memory.
  MBEDTLS_ERR_CIPHER_INVALID_PADDING       = $6200;  // Input data contains invalid padding and is rejected.
  MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED   = $6280;  // Decryption of block requires a full block.
  MBEDTLS_ERR_CIPHER_AUTH_FAILED           = $6300;  // Authentication failed (for AEAD modes).
  MBEDTLS_ERR_CIPHER_INVALID_CONTEXT       = $6380;  // The context is invalid. For example, because it was freed.
  MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED       = $6400;  // Cipher hardware accelerator failed.

  MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE      = $7080;  // The requested feature is not available.
  MBEDTLS_ERR_SSL_BAD_INPUT_DATA           = $7100;  // Bad input parameters to function.
  MBEDTLS_ERR_SSL_INVALID_MAC              = $7180;  // Verification of the message MAC failed.
  MBEDTLS_ERR_SSL_INVALID_RECORD           = $7200;  // An invalid SSL record was received.
  MBEDTLS_ERR_SSL_CONN_EOF                 = $7280;  // The connection indicated an EOF.
  MBEDTLS_ERR_SSL_UNKNOWN_CIPHER           = $7300;  // An unknown cipher was received.
  MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN         = $7380;  // The server has no ciphersuites in common with the client.
  MBEDTLS_ERR_SSL_NO_RNG                   = $7400;  // No RNG was provided to the SSL module.
  MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE    = $7480;  // No client certification received from the client, but required by the authentication mode.
  MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE    = $7500;  // Our own certificate(s) is/are too large to send in an SSL message.
  MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED     = $7580;  // The own certificate is not set, but needed by the server.
  MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED     = $7600;  // The own private key or pre-shared key is not set, but needed.
  MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED        = $7680;  // No CA Chain is set, but required to operate.
  MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE       = $7700;  // An unexpected message was received from our peer.
  MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE      = $7780;  // A fatal alert message was received from our peer.
  MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED       = $7800;  // Verification of our peer failed.
  MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY        = $7880;  // The peer notified us that the connection is going to be closed.
  MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO      = $7900;  // Processing of the ClientHello handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO      = $7980;  // Processing of the ServerHello handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE       = $7A00;  // Processing of the Certificate handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST = $7A80;  // Processing of the CertificateRequest handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE = $7B00;  // Processing of the ServerKeyExchange handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE = $7B80;  // Processing of the ServerHelloDone handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE = $7C00;  // Processing of the ClientKeyExchange handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP = $7C80;  // Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public.
  MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS = $7D00;  // Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret.
  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY = $7D80;  // Processing of the CertificateVerify handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC = $7E00;  // Processing of the ChangeCipherSpec handshake message failed.
  MBEDTLS_ERR_SSL_BAD_HS_FINISHED          = $7E80;  // Processing of the Finished handshake message failed.
  MBEDTLS_ERR_SSL_ALLOC_FAILED             = $7F00;  // Memory allocation failed
  MBEDTLS_ERR_SSL_HW_ACCEL_FAILED          = $7F80;  // Hardware acceleration function returned with error
  MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH     = $6F80;  // Hardware acceleration function skipped / left alone data
  MBEDTLS_ERR_SSL_COMPRESSION_FAILED       = $6F00;  // Processing of the compression / decompression failed
  MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION  = $6E80;  // Handshake protocol not within min/max boundaries
  MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET = $6E00;  // Processing of the NewSessionTicket handshake message failed.
  MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED   = $6D80;  // Session ticket has expired.
  MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH         = $6D00;  // Public key type mismatch (eg, asked for RSA key exchange and presented EC key)
  MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY         = $6C80;  // Unknown identity received (eg, PSK identity)
  MBEDTLS_ERR_SSL_INTERNAL_ERROR           = $6C00;  // Internal error (eg, unexpected failure in lower-level module)
  MBEDTLS_ERR_SSL_COUNTER_WRAPPING         = $6B80;  // A counter would wrap (eg, too many messages exchanged).
  MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO = $6B00;  // Unexpected message at ServerHello in renegotiation.
  MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED    = $6A80;  // DTLS client must retry for hello verification
  MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL         = $6A00;  // A buffer is too small to receive or write a message
  MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE    = $6980;  // None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages).
  MBEDTLS_ERR_SSL_WANT_READ                = $6900;  // Connection requires a read call.
  MBEDTLS_ERR_SSL_WANT_WRITE               = $6880;  // Connection requires a write call.
  MBEDTLS_ERR_SSL_TIMEOUT                  = $6800;  // The operation timed out.
  MBEDTLS_ERR_SSL_CLIENT_RECONNECT         = $6780;  // The client initiated a reconnect from the same port.
  MBEDTLS_ERR_SSL_UNEXPECTED_RECORD        = $6700;  // Record header looks valid but is not expected.
  MBEDTLS_ERR_SSL_NON_FATAL                = $6680;  // The alert message received indicates a non-fatal error.
  MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH      = $6600;  // Couldn't set the hash for verifying CertificateVerify

  (* Various constants *)

  MBEDTLS_SSL_MAJOR_VERSION_3              = 3;
  MBEDTLS_SSL_MINOR_VERSION_0              = 0;   // SSL v3.0
  MBEDTLS_SSL_MINOR_VERSION_1              = 1;   // TLS v1.0
  MBEDTLS_SSL_MINOR_VERSION_2              = 2;   // TLS v1.1
  MBEDTLS_SSL_MINOR_VERSION_3              = 3;   // TLS v1.2

  MBEDTLS_SSL_TRANSPORT_STREAM             = 0;   // TLS
  MBEDTLS_SSL_TRANSPORT_DATAGRAM           = 1;   // DTLS

  MBEDTLS_SSL_MAX_HOST_NAME_LEN            = 255; // Maximum host name defined in RFC 1035

  (* RFC 6066 section 4, see also mfl_code_to_length in ssl_tls.c
   * NONE must be zero so that memset()ing structure to zero works *)

  MBEDTLS_SSL_MAX_FRAG_LEN_NONE            = 0;   // don't use this extension
  MBEDTLS_SSL_MAX_FRAG_LEN_512             = 1;   // MaxFragmentLength 2^9
  MBEDTLS_SSL_MAX_FRAG_LEN_1024            = 2;   // MaxFragmentLength 2^10
  MBEDTLS_SSL_MAX_FRAG_LEN_2048            = 3;   // MaxFragmentLength 2^11
  MBEDTLS_SSL_MAX_FRAG_LEN_4096            = 4;   // MaxFragmentLength 2^12
  MBEDTLS_SSL_MAX_FRAG_LEN_INVALID         = 5;   // first invalid value

  MBEDTLS_SSL_IS_CLIENT                    = 0;
  MBEDTLS_SSL_IS_SERVER                    = 1;

  MBEDTLS_SSL_IS_NOT_FALLBACK              = 0;
  MBEDTLS_SSL_IS_FALLBACK                  = 1;

  MBEDTLS_SSL_EXTENDED_MS_DISABLED         = 0;
  MBEDTLS_SSL_EXTENDED_MS_ENABLED          = 1;

  MBEDTLS_SSL_ETM_DISABLED                 = 0;
  MBEDTLS_SSL_ETM_ENABLED                  = 1;

  MBEDTLS_SSL_COMPRESS_NULL                = 0;
  MBEDTLS_SSL_COMPRESS_DEFLATE             = 1;

  MBEDTLS_SSL_VERIFY_NONE                  = 0;
  MBEDTLS_SSL_VERIFY_OPTIONAL              = 1;
  MBEDTLS_SSL_VERIFY_REQUIRED              = 2;
  MBEDTLS_SSL_VERIFY_UNSET                 = 3; // Used only for sni_authmode

  MBEDTLS_SSL_LEGACY_RENEGOTIATION         = 0;
  MBEDTLS_SSL_SECURE_RENEGOTIATION         = 1;

  MBEDTLS_SSL_RENEGOTIATION_DISABLED       = 0;
  MBEDTLS_SSL_RENEGOTIATION_ENABLED        = 1;

  MBEDTLS_SSL_ANTI_REPLAY_DISABLED         = 0;
  MBEDTLS_SSL_ANTI_REPLAY_ENABLED          = 1;

  MBEDTLS_SSL_RENEGOTIATION_NOT_ENFORCED   = -1;
  MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT   = 16;

  MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION      = 0;
  MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION   = 1;
  MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE       = 2;

  MBEDTLS_SSL_TRUNC_HMAC_DISABLED          = 0;
  MBEDTLS_SSL_TRUNC_HMAC_ENABLED           = 1;
  MBEDTLS_SSL_TRUNCATED_HMAC_LEN           = 10;  // 80 bits, rfc 6066 section 7

  MBEDTLS_SSL_SESSION_TICKETS_DISABLED     = 0;
  MBEDTLS_SSL_SESSION_TICKETS_ENABLED      = 1;

  MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED = 0;
  MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED  = 1;

  MBEDTLS_SSL_ARC4_ENABLED                 = 0;
  MBEDTLS_SSL_ARC4_DISABLED                = 1;

  MBEDTLS_SSL_PRESET_DEFAULT               = 0;
  MBEDTLS_SSL_PRESET_SUITEB                = 2;

  MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED     = 1;
  MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED    = 0;

(*
 * Default range for DTLS retransmission timer value, in milliseconds.
 * RFC 6347 4.2.4.1 says from 1 second to 60 seconds.
 *)
  MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN         = 1000;
  MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX         = 60000;

  MBEDTLS_SSL_INITIAL_HANDSHAKE            = 0;
  MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS    = 1;   // In progress
  MBEDTLS_SSL_RENEGOTIATION_DONE           = 2;   // Done or aborted
  MBEDTLS_SSL_RENEGOTIATION_PENDING        = 3;   // Requested (server only)

  MBEDTLS_SSL_RETRANS_PREPARING            = 0;
  MBEDTLS_SSL_RETRANS_SENDING              = 1;
  MBEDTLS_SSL_RETRANS_WAITING              = 2;
  MBEDTLS_SSL_RETRANS_FINISHED             = 3;

  MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC       = 20;
  MBEDTLS_SSL_MSG_ALERT                    = 21;
  MBEDTLS_SSL_MSG_HANDSHAKE                = 22;
  MBEDTLS_SSL_MSG_APPLICATION_DATA         = 23;

  MBEDTLS_SSL_ALERT_LEVEL_WARNING          = 1;
  MBEDTLS_SSL_ALERT_LEVEL_FATAL            = 2;

  MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY       = 0;  // 0x00
  MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE = 10;  // 0x0A
  MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC     = 20;  // 0x14
  MBEDTLS_SSL_ALERT_MSG_DECRYPTION_FAILED  = 21;  // 0x15
  MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW    = 22;  // 0x16
  MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE = 30;  // 0x1E
  MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE  = 40;  // 0x28
  MBEDTLS_SSL_ALERT_MSG_NO_CERT            = 41;  // 0x29
  MBEDTLS_SSL_ALERT_MSG_BAD_CERT           = 42;  // 0x2A
  MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT   = 43;  // 0x2B
  MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED       = 44;  // 0x2C
  MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED       = 45;  // 0x2D
  MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN       = 46;  // 0x2E
  MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER  = 47;  // 0x2F
  MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA         = 48;  // 0x30
  MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED      = 49;  // 0x31
  MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR       = 50;  // 0x32
  MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR      = 51;  // 0x33
  MBEDTLS_SSL_ALERT_MSG_EXPORT_RESTRICTION = 60;  // 0x3C
  MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION   = 70;  // 0x46
  MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY = 71;  // 0x47
  MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR     = 80;  // 0x50
  MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK = 86;  // 0x56
  MBEDTLS_SSL_ALERT_MSG_USER_CANCELED      = 90;  // 0x5A
  MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION   = 100;  // 0x64
  MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT    = 110;  // 0x6E
  MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME  = 112;  // 0x70
  MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY = 115;  // 0x73
  MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL = 120; // 0x78

  MBEDTLS_SSL_HS_HELLO_REQUEST             = 0;
  MBEDTLS_SSL_HS_CLIENT_HELLO              = 1;
  MBEDTLS_SSL_HS_SERVER_HELLO              = 2;
  MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST      = 3;
  MBEDTLS_SSL_HS_NEW_SESSION_TICKET        = 4;
  MBEDTLS_SSL_HS_CERTIFICATE               = 11;
  MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE       = 12;
  MBEDTLS_SSL_HS_CERTIFICATE_REQUEST       = 13;
  MBEDTLS_SSL_HS_SERVER_HELLO_DONE         = 14;
  MBEDTLS_SSL_HS_CERTIFICATE_VERIFY        = 15;
  MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE       = 16;
  MBEDTLS_SSL_HS_FINISHED                  = 20;

  (* TLS extensions *)
  MBEDTLS_TLS_EXT_SERVERNAME               = 0;
  MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME      = 0;
  MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH      = 1;
  MBEDTLS_TLS_EXT_TRUNCATED_HMAC           = 4;
  MBEDTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES = 10;
  MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS  = 11;
  MBEDTLS_TLS_EXT_SIG_ALG                  = 13;
  MBEDTLS_TLS_EXT_ALPN                     = 16;
  MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC         = 22; // 0x16
  MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET   = $0017; // 23
  MBEDTLS_TLS_EXT_SESSION_TICKET           = 35;
  MBEDTLS_TLS_EXT_ECJPAKE_KKPP             = 256; // experimental
  MBEDTLS_TLS_EXT_RENEGOTIATION_INFO       = $FF01;

  MBEDTLS_SSL_HELLO_REQUEST                = 0;
  MBEDTLS_SSL_CLIENT_HELLO                 = 1;
  MBEDTLS_SSL_SERVER_HELLO                 = 2;
  MBEDTLS_SSL_SERVER_CERTIFICATE           = 3;
  MBEDTLS_SSL_SERVER_KEY_EXCHANGE          = 4;
  MBEDTLS_SSL_CERTIFICATE_REQUEST          = 5;
  MBEDTLS_SSL_SERVER_HELLO_DONE            = 6;
  MBEDTLS_SSL_CLIENT_CERTIFICATE           = 7;
  MBEDTLS_SSL_CLIENT_KEY_EXCHANGE          = 8;
  MBEDTLS_SSL_CERTIFICATE_VERIFY           = 9;
  MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC    = 10;
  MBEDTLS_SSL_CLIENT_FINISHED              = 11;
  MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC    = 12;
  MBEDTLS_SSL_SERVER_FINISHED              = 13;
  MBEDTLS_SSL_FLUSH_BUFFERS                = 14;
  MBEDTLS_SSL_HANDSHAKE_WRAPUP             = 15;
  MBEDTLS_SSL_HANDSHAKE_OVER               = 16;
  MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET    = 17;
  MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT = 18;

  MBEDTLS_ENTROPY_SOURCE_STRONG            = 1;  // Entropy source is strong
  MBEDTLS_ENTROPY_SOURCE_WEAK              = 0;  // Entropy source is weak

var
  mbedtls_test_cas_pem : PChar; external;
  mbedtls_test_ca_crt : PChar; external;
  mbedtls_test_ca_key : PChar; external;
  mbedtls_test_ca_pwd : PChar; external;
  mbedtls_test_srv_crt : PChar; external;
  mbedtls_test_srv_key : PChar; external;
  mbedtls_test_cli_crt : PChar; external;
  mbedtls_test_cli_key : PChar; external;

  mbedtls_test_cas : array [0 .. 0] of PChar; external; // List of all CA certificates, terminated by NULL

  mbedtls_test_cas_pem_len : size_t; external;
  mbedtls_test_ca_crt_len : size_t; external;
  mbedtls_test_ca_key_len : size_t; external;
  mbedtls_test_ca_pwd_len : size_t; external;
  mbedtls_test_srv_crt_len : size_t; external;
  mbedtls_test_srv_key_len : size_t; external;
  mbedtls_test_cli_crt_len : size_t; external;
  mbedtls_test_cli_key_len : size_t; external;

  mbedtls_test_cas_len : array [0 .. 0] of size_t; external;

function mbedtls_ssl_close_notify (ssl : Pmbedtls_ssl_context) : integer; cdecl; external;
procedure mbedtls_ssl_free (ssl : Pmbedtls_ssl_context); cdecl; external;
function mbedtls_ssl_get_verify_result (ssl : Pmbedtls_ssl_context) : uint32_t; cdecl; external;
function mbedtls_ssl_get_ciphersuite (const ssl : Pmbedtls_ssl_context) : PChar; cdecl; external;
function mbedtls_ssl_get_version (const ssl : Pmbedtls_ssl_context) : PChar; cdecl; external;
function mbedtls_ssl_get_max_frag_len (const ssl : Pmbedtls_ssl_context) : size_t; cdecl; external;
function mbedtls_ssl_get_peer_cert (const ssl : Pmbedtls_ssl_context) : Pmbedtls_x509_crt; cdecl; external;
function mbedtls_ssl_get_session (const ssl : Pmbedtls_ssl_context; session : Pmbedtls_ssl_session) : integer; cdecl; external;
function mbedtls_ssl_get_ciphersuite_name (const ciphersuite_id : integer) : PChar; cdecl; external;
function mbedtls_ssl_get_ciphersuite_id (const ciphersuite_name : PChar) : integer; cdecl; external;
function mbedtls_ssl_handshake (ssl : Pmbedtls_ssl_context) : integer; cdecl; external;
procedure mbedtls_ssl_init (ssl : Pmbedtls_ssl_context); cdecl; external;
function mbedtls_ssl_list_ciphersuites : PInteger; cdecl; external;
function mbedtls_ssl_read (ssl : Pmbedtls_ssl_context; buf : pointer; len : size_t) : integer; cdecl; external;
function mbedtls_ssl_set_hostname (ssl : Pmbedtls_ssl_context; hostname : PChar) : integer; cdecl; external;
procedure mbedtls_ssl_set_bio (ssl : Pmbedtls_ssl_context; p_bio : pointer;
                               f_send : TNetSendFunc; f_recv : TNetRecvFunc;
                               f_recv_timeout : TNetRecvTimeoutFunc); cdecl; external;
procedure mbedtls_ssl_set_timer_cb (ssl : Pmbedtls_ssl_context; p_timer : pointer;
                                    f_set_timer : TSetTimerFunc;
                                    f_get_timer : TGetTimerFunc); cdecl; external;
function mbedtls_ssl_setup (ssl : Pmbedtls_ssl_context; conf : Pmbedtls_ssl_config) : integer; cdecl; external;
function mbedtls_ssl_write (ssl : Pmbedtls_ssl_context; const buf : pointer; len : size_t) : integer; cdecl; external;

procedure mbedtls_ssl_config_init (conf : Pmbedtls_ssl_config); cdecl; external;
function mbedtls_ssl_config_defaults (conf : Pmbedtls_ssl_config; endpoint : integer;
                                      transport : integer; preset : integer) : integer; cdecl; external;
procedure mbedtls_ssl_conf_authmode (conf : Pmbedtls_ssl_config; authmode : integer); cdecl; external;
procedure mbedtls_ssl_conf_ca_chain (conf : Pmbedtls_ssl_config; ca_chain : Pmbedtls_x509_crt;
                                     ca_crl : Pmbedtls_x509_crl); cdecl; external;
procedure mbedtls_ssl_conf_transport (conf : Pmbedtls_ssl_config; transport : integer); cdecl; external;
procedure mbedtls_ssl_conf_rng (conf : Pmbedtls_ssl_config; f_rng : TrngFunc; p_rng : pointer); cdecl; external;
procedure mbedtls_ssl_conf_dbg (conf : Pmbedtls_ssl_config; f_dbg : TdbgFunc; p_dbg : pointer); cdecl; external;
procedure mbedtls_ssl_config_free (conf : Pmbedtls_ssl_config); cdecl; external;

function mbedtls_ssl_session_reset (ssl : Pmbedtls_ssl_context) : integer; cdecl; external;
function mbedtls_ssl_set_session (ssl : Pmbedtls_ssl_context; const session : Pmbedtls_ssl_session) : integer; cdecl; external;
procedure mbedtls_ssl_conf_max_version (conf : Pmbedtls_ssl_config; major, minor : integer); cdecl; external;
procedure mbedtls_ssl_conf_min_version (conf : Pmbedtls_ssl_config; major, minor : integer); cdecl; external;
function mbedtls_ssl_get_bytes_avail (ssl : Pmbedtls_ssl_context) : size_t; cdecl; external;

function mbedtls_entropy_add_source (ctx : Pmbedtls_entropy_context;
                                     f_source : TEntropyFunc; p_source : pointer;
                                     threshold : size_t; strong : integer) : integer; cdecl; external;
procedure mbedtls_entropy_free (ctx : Pmbedtls_entropy_context); cdecl; external;
function mbedtls_entropy_func (data : pointer; output : PChar; len : size_t) : integer; cdecl; external;
procedure mbedtls_entropy_init (ctx : Pmbedtls_entropy_context); cdecl; external;

procedure mbedtls_ctr_drbg_init (ctx : Pmbedtls_ctr_drbg_context); cdecl; external;
function mbedtls_ctr_drbg_seed (ctx : Pmbedtls_ctr_drbg_context; f_entropy : TEntropyFunc; p_entropy : pointer;
                                custom : PChar; len : size_t) : integer; cdecl; external;
function mbedtls_ctr_drbg_random_with_add (p_rng : pointer; output : PChar; output_len : size_t;
                                           additional : PChar; add_len : size_t) : integer; cdecl; external;
function mbedtls_ctr_drbg_random (p_rng : pointer;  output : PChar; output_len : size_t) : integer; cdecl; external;
procedure mbedtls_ctr_drbg_free (ctx : Pmbedtls_ctr_drbg_context); cdecl; external;

procedure mbedtls_x509_crt_init (crt : Pmbedtls_x509_crt); cdecl; external;
procedure mbedtls_x509_crt_free (crt : Pmbedtls_x509_crt); cdecl; external;
function mbedtls_x509_crt_parse (chain : Pmbedtls_x509_crt; buf : PChar; buflen : size_t) : integer; cdecl; external;
function mbedtls_x509_crt_parse_file (chain : Pmbedtls_x509_crt; const path : PChar) : integer; cdecl; external;
function mbedtls_x509_crt_parse_path (chain : Pmbedtls_x509_crt; const path : PChar) : integer; cdecl; external;
function mbedtls_x509_crt_verify_info (buf : PChar; size_ : size_t; const prefix : PChar;
                                       flags : uint32_t) : integer; cdecl; external;

function mbedtls_version_get_number : integer; cdecl; external;
procedure mbedtls_version_get_string (string_ : PChar); cdecl; external;
procedure mbedtls_version_get_string_full (string_ : PChar); cdecl; external;

function ErrToStr (e : integer) : string;

procedure mytests; cdecl; external;
procedure openwww; cdecl; external;
procedure readwww; cdecl; external;
procedure closewww; cdecl; external;
procedure fillsession (ses : Pmbedtls_ssl_session); cdecl; external;

implementation

function ErrToStr (e : integer) : string;
begin
  case abs (e) of
    MBEDTLS_ERR_MPI_FILE_IO_ERROR          : Result := 'An error occurred while reading from or writing to a file.';
    MBEDTLS_ERR_MPI_BAD_INPUT_DATA         : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_MPI_INVALID_CHARACTER      : Result := 'There is an invalid character in the digit string.';
    MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL       : Result := 'The buffer is too small to write to.';
    MBEDTLS_ERR_MPI_NEGATIVE_VALUE         : Result := 'The input arguments are negative or result in illegal output.';
    MBEDTLS_ERR_MPI_DIVISION_BY_ZERO       : Result := 'The input argument for division is zero, which is not allowed.';
    MBEDTLS_ERR_MPI_NOT_ACCEPTABLE         : Result := 'The input arguments are not acceptable.';
    MBEDTLS_ERR_MPI_ALLOC_FAILED           : Result := 'Memory allocation failed.';

    MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG  : Result := 'Too many random requested in single call.';
    MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG    : Result := 'Input too large (Entropy + additional).';
    MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR    : Result := 'Read/write error in file.';
    MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED : Result := 'The entropy source failed.';

    MBEDTLS_ERR_CCM_BAD_INPUT              : Result := 'Bad input parameters to the function.';
    MBEDTLS_ERR_CCM_AUTH_FAILED            : Result := 'Authenticated decryption failed.';
    MBEDTLS_ERR_CCM_HW_ACCEL_FAILED        : Result := 'CCM hardware accelerator failed.';

    MBEDTLS_ERR_GCM_AUTH_FAILED            : Result := 'Authenticated decryption failed.';
    MBEDTLS_ERR_GCM_HW_ACCEL_FAILED        : Result := 'GCM hardware accelerator failed.';
    MBEDTLS_ERR_GCM_BAD_INPUT              : Result := 'Bad input parameters to function.';

    MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH : Result := 'Invalid key length.';
    MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED   : Result := 'Blowfish hardware accelerator failed.';
    MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH : Result := 'Invalid data input length.';

    MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED       : Result := 'ARC4 hardware accelerator failed.';

    MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE : Result := 'The selected feature is not available.';
    MBEDTLS_ERR_THREADING_BAD_INPUT_DATA   : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_THREADING_MUTEX_ERROR      : Result := 'Locking / unlocking / free failed with error code.';

    MBEDTLS_ERR_AES_INVALID_KEY_LENGTH     : Result := 'Invalid key length.';
    MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH   : Result := 'Invalid data input length.';

    MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE    : Result := 'Feature not available. For example, an unsupported AES key size.';
    MBEDTLS_ERR_AES_HW_ACCEL_FAILED        : Result := 'AES hardware accelerator failed.';

    MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH : Result := 'Invalid key length.';
    MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH : Result := 'Invalid data input length.';
    MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED : Result := 'Camellia hardware accelerator failed.';

    MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH  : Result := 'The data input has an invalid length.';
    MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED       : Result := 'XTEA hardware accelerator failed.';

    MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL    : Result := 'Output buffer too small.';
    MBEDTLS_ERR_BASE64_INVALID_CHARACTER   : Result := 'Invalid character in input.';

    MBEDTLS_ERR_MD2_HW_ACCEL_FAILED        : Result := 'MD2 hardware accelerator failed.';
    MBEDTLS_ERR_MD4_HW_ACCEL_FAILED        : Result := 'MD4 hardware accelerator failed.';
    MBEDTLS_ERR_MD5_HW_ACCEL_FAILED        : Result := 'MD5 hardware accelerator failed.';

    MBEDTLS_ERR_OID_NOT_FOUND              : Result := 'OID is not found.';
    MBEDTLS_ERR_OID_BUF_TOO_SMALL          : Result := 'Output buffer is too small.';

    MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED    : Result := 'Input data should be aligned.';

    MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED  : Result := 'RIPEMD160 hardware accelerator failed.';

    MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH   : Result := 'The data input has an invalid length.';
    MBEDTLS_ERR_DES_HW_ACCEL_FAILED        : Result := 'DES hardware accelerator failed.';

    MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED : Result := 'The entropy source failed.';
    MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG   : Result := 'The requested random buffer length is too big.';
    MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG     : Result := 'The input (entropy + additional data) is too large.';
    MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR     : Result := 'Read or write error in file.';

    MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED       : Result := 'SHA-1 hardware accelerator failed.';
    MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED     : Result := 'SHA-256 hardware accelerator failed.';
    MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED     : Result := 'SHA-512 hardware accelerator failed.';

    MBEDTLS_ERR_ENTROPY_SOURCE_FAILED      : Result := 'Critical entropy source failure.';
    MBEDTLS_ERR_ENTROPY_MAX_SOURCES        : Result := 'No more sources can be added.';
    MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED : Result := 'No sources have been added to poll.';
    MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE   : Result := 'No strong sources have been added to poll.';
    MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR      : Result := 'Read/write error in file.';

    MBEDTLS_ERR_NET_SOCKET_FAILED          : Result := 'Failed to open a socket.';
    MBEDTLS_ERR_NET_CONNECT_FAILED         : Result := 'The connection to the given server / port failed.';
    MBEDTLS_ERR_NET_BIND_FAILED            : Result := 'Binding of the socket failed.';
    MBEDTLS_ERR_NET_LISTEN_FAILED          : Result := 'Could not listen on the socket.';
    MBEDTLS_ERR_NET_ACCEPT_FAILED          : Result := 'Could not accept the incoming connection.';
    MBEDTLS_ERR_NET_RECV_FAILED            : Result := 'Reading information from the socket failed.';
    MBEDTLS_ERR_NET_SEND_FAILED            : Result := 'Sending information through the socket failed.';
    MBEDTLS_ERR_NET_CONN_RESET             : Result := 'Connection was reset by peer.';
    MBEDTLS_ERR_NET_UNKNOWN_HOST           : Result := 'Failed to get an IP address for the given hostname.';
    MBEDTLS_ERR_NET_BUFFER_TOO_SMALL       : Result := 'Buffer is too small to hold the data.';
    MBEDTLS_ERR_NET_INVALID_CONTEXT        : Result := 'The context is invalid, eg because it was free()ed.';

    MBEDTLS_ERR_ASN1_OUT_OF_DATA           : Result := 'Out of data when parsing an ASN1 data structure.';
    MBEDTLS_ERR_ASN1_UNEXPECTED_TAG        : Result := 'ASN1 tag was of an unexpected value.';
    MBEDTLS_ERR_ASN1_INVALID_LENGTH        : Result := 'Error when trying to determine the length or invalid length.';
    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH       : Result := 'Actual length differs from expected length.';
    MBEDTLS_ERR_ASN1_INVALID_DATA          : Result := 'Data is invalid. (not used)';
    MBEDTLS_ERR_ASN1_ALLOC_FAILED          : Result := 'Memory allocation failed.';
    MBEDTLS_ERR_ASN1_BUF_TOO_SMALL         : Result := 'Buffer too small when writing ASN.1 data structure.';

    MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED       : Result := 'CMAC hardware accelerator failed.';

    MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT : Result := 'No PEM header or footer found.';
    MBEDTLS_ERR_PEM_INVALID_DATA           : Result := 'PEM string is not as expected.';
    MBEDTLS_ERR_PEM_ALLOC_FAILED           : Result := 'Failed to allocate memory.';
    MBEDTLS_ERR_PEM_INVALID_ENC_IV         : Result := 'RSA IV is not in hex-format.';
    MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG        : Result := 'Unsupported key encryption algorithm.';
    MBEDTLS_ERR_PEM_PASSWORD_REQUIRED      : Result := 'Private key password can''t be empty.';
    MBEDTLS_ERR_PEM_PASSWORD_MISMATCH      : Result := 'Given private key password does not allow for correct decryption.';
    MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE    : Result := 'Unavailable feature, e.g. hashing/encryption combination.';
    MBEDTLS_ERR_PEM_BAD_INPUT_DATA         : Result := 'Bad input parameters to function.';

    MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA      : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE : Result := 'Feature not available, e.g. unsupported encryption scheme.';
    MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT  : Result := 'PBE ASN. data not as expected.';
    MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH   : Result := 'Given private key password does not allow for correct decryption.';

    MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE   : Result := 'Unavailable feature, e.g. RSA hashing/encryption combination.';
    MBEDTLS_ERR_X509_UNKNOWN_OID           : Result := 'Requested OID is unknown.';
    MBEDTLS_ERR_X509_INVALID_FORMAT        : Result := 'The CRT/CRL/CSR format is invalid, e.g. different type expected.';
    MBEDTLS_ERR_X509_INVALID_VERSION       : Result := 'The CRT/CRL/CSR version element is invalid.';
    MBEDTLS_ERR_X509_INVALID_SERIAL        : Result := 'The serial tag or value is invalid.';
    MBEDTLS_ERR_X509_INVALID_ALG           : Result := 'The algorithm tag or value is invalid.';
    MBEDTLS_ERR_X509_INVALID_NAME          : Result := 'The name tag or value is invalid.';
    MBEDTLS_ERR_X509_INVALID_DATE          : Result := 'The date tag or value is invalid.';
    MBEDTLS_ERR_X509_INVALID_SIGNATURE     : Result := 'The signature tag or value invalid.';
    MBEDTLS_ERR_X509_INVALID_EXTENSIONS    : Result := 'The extension tag or value is invalid.';
    MBEDTLS_ERR_X509_UNKNOWN_VERSION       : Result := 'CRT/CRL/CSR has an unsupported version number.';
    MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG       : Result := 'Signature algorithm (oid) is unsupported.';
    MBEDTLS_ERR_X509_SIG_MISMATCH          : Result := 'Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid)';
    MBEDTLS_ERR_X509_CERT_VERIFY_FAILED    : Result := 'Certificate verification failed, e.g. CRL, CA or signature check failed.';
    MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT   : Result := 'Format not recognized as DER or PEM.';
    MBEDTLS_ERR_X509_BAD_INPUT_DATA        : Result := 'Input invalid.';
    MBEDTLS_ERR_X509_ALLOC_FAILED          : Result := 'Allocation of memory failed.';
    MBEDTLS_ERR_X509_FILE_IO_ERROR         : Result := 'Read/write of file failed.';
    MBEDTLS_ERR_X509_BUFFER_TOO_SMALL      : Result := 'Destination buffer is too small.';
    MBEDTLS_ERR_X509_FATAL_ERROR           : Result := 'A fatal error occured, eg the chain is too long or the vrfy callback failed.';

    MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA       : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_PKCS5_INVALID_FORMAT       : Result := 'Unexpected ASN.1 data.';
    MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE  : Result := 'Requested encryption or digest alg not available.';
    MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH    : Result := 'Given private key password does not allow for correct decryption.';

    MBEDTLS_ERR_DHM_BAD_INPUT_DATA         : Result := 'Bad input parameters.';
    MBEDTLS_ERR_DHM_READ_PARAMS_FAILED     : Result := 'Reading of the DHM parameters failed.';
    MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED     : Result := 'Making of the DHM parameters failed.';
    MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED     : Result := 'Reading of the public values failed.';
    MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED     : Result := 'Making of the public value failed.';
    MBEDTLS_ERR_DHM_CALC_SECRET_FAILED     : Result := 'Calculation of the DHM secret failed.';
    MBEDTLS_ERR_DHM_INVALID_FORMAT         : Result := 'The ASN.1 data is not formatted correctly.';
    MBEDTLS_ERR_DHM_ALLOC_FAILED           : Result := 'Allocation of memory failed.';
    MBEDTLS_ERR_DHM_FILE_IO_ERROR          : Result := 'Read or write of file failed.';
    MBEDTLS_ERR_DHM_HW_ACCEL_FAILED        : Result := 'DHM hardware accelerator failed.';
    MBEDTLS_ERR_DHM_SET_GROUP_FAILED       : Result := 'Setting the modulus and generator failed.';

    MBEDTLS_ERR_PK_ALLOC_FAILED            : Result := 'Memory allocation failed.';
    MBEDTLS_ERR_PK_TYPE_MISMATCH           : Result := 'Type mismatch, eg attempt to encrypt with an ECDSA key.';
    MBEDTLS_ERR_PK_BAD_INPUT_DATA          : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_PK_FILE_IO_ERROR           : Result := 'Read/write of file failed.';
    MBEDTLS_ERR_PK_KEY_INVALID_VERSION     : Result := 'Unsupported key version.';
    MBEDTLS_ERR_PK_KEY_INVALID_FORMAT      : Result := 'Invalid key tag or value.';
    MBEDTLS_ERR_PK_UNKNOWN_PK_ALG          : Result := 'Key algorithm is unsupported (only RSA and EC are supported).';
    MBEDTLS_ERR_PK_PASSWORD_REQUIRED       : Result := 'Private key password can''t be empty.';
    MBEDTLS_ERR_PK_PASSWORD_MISMATCH       : Result := 'Given private key password does not allow for correct decryption.';
    MBEDTLS_ERR_PK_INVALID_PUBKEY          : Result := 'The pubkey tag or value is invalid (only RSA and EC are supported).';
    MBEDTLS_ERR_PK_INVALID_ALG             : Result := 'The algorithm tag or value is invalid.';
    MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE     : Result := 'Elliptic curve is unsupported (only NIST curves are supported).';
    MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE     : Result := 'Unavailable feature, e.g. RSA disabled for RSA key.';
    MBEDTLS_ERR_PK_SIG_LEN_MISMATCH        : Result := 'The signature is valid but its length is less than expected.';
    MBEDTLS_ERR_PK_HW_ACCEL_FAILED         : Result := 'PK hardware accelerator failed.';

    MBEDTLS_ERR_RSA_BAD_INPUT_DATA         : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_RSA_INVALID_PADDING        : Result := 'Input data contains invalid padding and is rejected.';
    MBEDTLS_ERR_RSA_KEY_GEN_FAILED         : Result := 'Something failed during generation of a key.';
    MBEDTLS_ERR_RSA_KEY_CHECK_FAILED       : Result := 'Key failed to pass the validity check of the library.';
    MBEDTLS_ERR_RSA_PUBLIC_FAILED          : Result := 'The public key operation failed.';
    MBEDTLS_ERR_RSA_PRIVATE_FAILED         : Result := 'The private key operation failed.';
    MBEDTLS_ERR_RSA_VERIFY_FAILED          : Result := 'The PKCS#1 verification failed.';
    MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE       : Result := 'The output buffer for decryption is not large enough.';
    MBEDTLS_ERR_RSA_RNG_FAILED             : Result := 'The random generator failed to generate non-zeros.';
    MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION  : Result := 'The implementation does not offer the requested operation, for example, because of security violations or lack of functionality.';
    MBEDTLS_ERR_RSA_HW_ACCEL_FAILED        : Result := 'RSA hardware accelerator failed.';

    MBEDTLS_ERR_ECP_BAD_INPUT_DATA         : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL       : Result := 'The buffer is too small to write to.';
    MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE    : Result := 'Requested curve not available.';
    MBEDTLS_ERR_ECP_VERIFY_FAILED          : Result := 'The signature is not valid.';
    MBEDTLS_ERR_ECP_ALLOC_FAILED           : Result := 'Memory allocation failed.';
    MBEDTLS_ERR_ECP_RANDOM_FAILED          : Result := 'Generation of random value, such as (ephemeral) key, failed.';
    MBEDTLS_ERR_ECP_INVALID_KEY            : Result := 'Invalid private or public key.';
    MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH       : Result := 'Signature is valid but shorter than the user-supplied length.';
    MBEDTLS_ERR_ECP_HW_ACCEL_FAILED        : Result := 'ECP hardware accelerator failed.';

    MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE     : Result := 'The selected feature is not available.';
    MBEDTLS_ERR_MD_BAD_INPUT_DATA          : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_MD_ALLOC_FAILED            : Result := 'Failed to allocate memory.';
    MBEDTLS_ERR_MD_FILE_IO_ERROR           : Result := 'Opening or reading of file failed.';
    MBEDTLS_ERR_MD_HW_ACCEL_FAILED         : Result := 'MD hardware accelerator failed.';

    MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE : Result := 'The selected feature is not available.';
    MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA      : Result := 'Bad input parameters.';
    MBEDTLS_ERR_CIPHER_ALLOC_FAILED        : Result := 'Failed to allocate memory.';
    MBEDTLS_ERR_CIPHER_INVALID_PADDING     : Result := 'Input data contains invalid padding and is rejected.';
    MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED : Result := 'Decryption of block requires a full block.';
    MBEDTLS_ERR_CIPHER_AUTH_FAILED         : Result := 'Authentication failed (for AEAD modes).';
    MBEDTLS_ERR_CIPHER_INVALID_CONTEXT     : Result := 'The context is invalid. For example, because it was freed.';
    MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED     : Result := 'Cipher hardware accelerator failed.';

    MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE    : Result := 'The requested feature is not available.';
    MBEDTLS_ERR_SSL_BAD_INPUT_DATA         : Result := 'Bad input parameters to function.';
    MBEDTLS_ERR_SSL_INVALID_MAC            : Result := 'Verification of the message MAC failed.';
    MBEDTLS_ERR_SSL_INVALID_RECORD         : Result := 'An invalid SSL record was received.';
    MBEDTLS_ERR_SSL_CONN_EOF               : Result := 'The connection indicated an EOF.';
    MBEDTLS_ERR_SSL_UNKNOWN_CIPHER         : Result := 'An unknown cipher was received.';
    MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN       : Result := 'The server has no ciphersuites in common with the client.';
    MBEDTLS_ERR_SSL_NO_RNG                 : Result := 'No RNG was provided to the SSL module.';
    MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE  : Result := 'No client certification received from the client, but required by the authentication mode.';
    MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE  : Result := 'Our own certificate(s) is/are too large to send in an SSL message.';
    MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED   : Result := 'The own certificate is not set, but needed by the server.';
    MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED   : Result := 'The own private key or pre-shared key is not set, but needed.';
    MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED      : Result := 'No CA Chain is set, but required to operate.';
    MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE     : Result := 'An unexpected message was received from our peer.';
    MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE    : Result := 'A fatal alert message was received from our peer.';
    MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED     : Result := 'Verification of our peer failed.';
    MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY      : Result := 'The peer notified us that the connection is going to be closed.';
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO    : Result := 'Processing of the ClientHello handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO    : Result := 'Processing of the ServerHello handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE     : Result := 'Processing of the Certificate handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST : Result := 'Processing of the CertificateRequest handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE : Result := 'Processing of the ServerKeyExchange handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE : Result := 'Processing of the ServerHelloDone handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE : Result := 'Processing of the ClientKeyExchange handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP : Result := 'Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public.';
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS : Result := 'Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret.';
    MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY : Result := 'Processing of the CertificateVerify handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC : Result := 'Processing of the ChangeCipherSpec handshake message failed.';
    MBEDTLS_ERR_SSL_BAD_HS_FINISHED        : Result := 'Processing of the Finished handshake message failed.';
    MBEDTLS_ERR_SSL_ALLOC_FAILED           : Result := 'Memory allocation failed.';
    MBEDTLS_ERR_SSL_HW_ACCEL_FAILED        : Result := 'Hardware acceleration function returned with error.';
    MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH   : Result := 'Hardware acceleration function skipped / left alone data.';
    MBEDTLS_ERR_SSL_COMPRESSION_FAILED     : Result := 'Processing of the compression / decompression failed.';
    MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION : Result := 'Handshake protocol not within min/max boundaries.';
    MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET : Result := 'Processing of the NewSessionTicket handshake message failed.';
    MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED : Result := 'Session ticket has expired.';
    MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH       : Result := 'Public key type mismatch (eg, asked for RSA key exchange and presented EC key).';
    MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY       : Result := 'Unknown identity received (eg, PSK identity).';
    MBEDTLS_ERR_SSL_INTERNAL_ERROR         : Result := 'Internal error (eg, unexpected failure in lower-level module).';
    MBEDTLS_ERR_SSL_COUNTER_WRAPPING       : Result := 'A counter would wrap (eg, too many messages exchanged).';
    MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO : Result := 'Unexpected message at ServerHello in renegotiation.';
    MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED  : Result := 'DTLS client must retry for hello verification.';
    MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL       : Result := 'A buffer is too small to receive or write a message.';
    MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE  : Result := 'None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages).';
    MBEDTLS_ERR_SSL_WANT_READ              : Result := 'Connection requires a read call.';
    MBEDTLS_ERR_SSL_WANT_WRITE             : Result := 'Connection requires a write call.';
    MBEDTLS_ERR_SSL_TIMEOUT                : Result := 'The operation timed out.';
    MBEDTLS_ERR_SSL_CLIENT_RECONNECT       : Result := 'The client initiated a reconnect from the same port.';
    MBEDTLS_ERR_SSL_UNEXPECTED_RECORD      : Result := 'Record header looks valid but is not expected.';
    MBEDTLS_ERR_SSL_NON_FATAL              : Result := 'The alert message received indicates a non-fatal error.';
    MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH    : Result := 'Couldn''t set the hash for verifying CertificateVerify.';
    else                                     Result := 'Unknown error (' + abs (e).ToHexString (4) + ').';
  end;
end;

end.

