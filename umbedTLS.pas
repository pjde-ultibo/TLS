unit umbedTLS;

{$mode objfpc}{$H+}

(* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
    stuffing : array [0..207] of byte;
  end;

  mbedtls_ssl_config = record // size 208
    stuffing : array [0..207] of byte;
  end;

  mbedtls_ssl_context = record // size 264
    stuffing : array [0..263] of byte;
  end;

const
(* SSL Error codes  - actually negative of these *)
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

  MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT = $1080;  // No PEM header or footer found.
  MBEDTLS_ERR_PEM_INVALID_DATA             = $1100;  // PEM string is not as expected.
  MBEDTLS_ERR_PEM_ALLOC_FAILED             = $1180;  // Failed to allocate memory.
  MBEDTLS_ERR_PEM_INVALID_ENC_IV           = $1200;  // RSA IV is not in hex-format.
  MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG          = $1280;  // Unsupported key encryption algorithm.
  MBEDTLS_ERR_PEM_PASSWORD_REQUIRED        = $1300;  // Private key password can't be empty.
  MBEDTLS_ERR_PEM_PASSWORD_MISMATCH        = $1380;  // Given private key password does not allow for correct decryption.
  MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE      = $1400;  // Unavailable feature, e.g. hashing/encryption combination.
  MBEDTLS_ERR_PEM_BAD_INPUT_DATA           = $1480;  // Bad input parameters to function.

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
  mbedtls_test_cas_pem : array [0..0] of char; external;
  mbedtls_test_cas_pem_len : size_t; external;


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


procedure mytests; cdecl; external;
procedure openwww; cdecl; external;
procedure readwww; cdecl; external;
procedure closewww; cdecl; external;
procedure fillsession (ses : Pmbedtls_ssl_session); cdecl; external;

implementation


end.

