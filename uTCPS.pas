unit uTCPS;

{$mode delphi}{$H+}

(*
  TCPSClient component based on TWinsock2TCPClient and mbedTLS library.

  pjde 2018

  TWinsock2TCPClient (c) 2015 SoftOz Pty. Ltd.     LGPLv2.1 with static linking exception
  mbedTLS            (C) 2006-2015, ARM Limited    Apache-2.0

  https://restdb.io/docs/quick-start
*)

interface

uses
  Classes, SysUtils, Winsock2, umbedTLS;

const
  ny : array [boolean] of string = ('NO', 'YES');

type

  TTCPSDebugEvent = procedure (Sender : TObject; level : integer; s : string) of object;
  TTCPSVerifyEvent = procedure (Sender : TObject; Flags : LongWord; var Allow : boolean) of object;
  TTCPSAppReadEvent = procedure (Sender : TObject; buf : pointer; len : cardinal) of object;
  TTCPSConnectEvent = procedure (Sender : TObject; Vers, Suite : string) of object;

  { TTCPSReadThread }

  TTCPSClient = class;

  TTCPSReadThread = class (TThread)
    Owner : TTCPSClient;
    constructor Create (anOwner : TTCPSClient);
    procedure Execute; override;
  end;

  { TTCPSClient }

  TTCPSClient = class (TWinsock2TCPClient)
    ssl : mbedtls_ssl_context;
    conf : mbedtls_ssl_config;
    cacert : mbedtls_x509_crt;
    ctr_drbg : mbedtls_ctr_drbg_context;
    entropy : mbedtls_entropy_context;
    pers : array [0..11] of char;
    FUseSSL : boolean;            // not yet implemented
    FOnVerify : TTCPSVerifyEvent;
    FOnDebug : TTCPSDebugEvent;
    FOnAppRead : TTCPSAppReadEvent;
    FOnConnect : TTCPSConnectEvent;
    FOnDisconnect : TNotifyEvent;
    HostName : string;
    ReadThread : TTCPSReadThread;
    Seeded : boolean;
    Initialised : boolean;
    procedure ReadThreadTerminated (Sender : TObject);
  public
    CipherVers : string;
    CipherSuite : string;
    CAFile : string;
    constructor Create;
    destructor Destroy; override;
    function Connect : boolean; override;
    procedure TidyUp;
    function Issues (code : Longword) : TStringList;
    procedure AppWrite (buf : pointer; len : cardinal); overload;
    procedure AppWrite (s : string); overload;
    procedure AppClose;
    procedure Seed;
    property UseSSL : boolean read FUseSSL write FUseSSL;
    property OnVerify : TTCPSVerifyEvent read FOnVerify write FOnVerify;
    property OnDebug : TTCPSDebugEvent read FOnDebug write FOnDebug;
    property OnAppRead : TTCPSAppReadEvent read FOnAppRead write FOnAppRead;
    property OnConnect : TTCPSConnectEvent read  FOnConnect write FOnConnect;
    property OnDisconnect : TNotifyEvent read FOnDisconnect write FOnDisconnect;
  end;

implementation

uses uLog, Platform;

function RandomSource (data : pointer; output : PChar; len : size_t) : integer; cdecl;
var            // entropy source based on random ()
  x, i, r : integer;
begin
  Log ('RANDOM SOURCE - length ' + len.ToString);
  i := 0;
  repeat
    x := random ($ffffffff);
    if i + 4 <= len then r := 4 else r := len - i;
    Move (x, output[i], r);
    i := i + 4;
  until i >= len;
  Result := 0;
end;

function RandomReadSource (data : pointer; output : PChar; len : size_t) : integer; cdecl;
var            // entropy source based on randomread ()
  i, r : integer;
  x : int64;
begin
  Log ('RANDOM READ SOURCE - length ' + len.ToString);
  i := 0;
  repeat
    x := RandomReadInt64 ($ffffffff);
    if i + 4 <= len then r := 4 else r := len - i;
    Move (x, output[i], r);
    i := i + 4;
  until i >= len;
  Result := 0;
end;

function NetSend (ctx : pointer; buf : pointer; len : size_t) : integer; cdecl;
var
  cl : TTCPSClient;
begin
//  Log ('net send ' + len.ToString);
  cl := TTCPSClient (ctx);
  if cl.WriteData (buf, len) then
    Result := len
  else
    Result := -MBEDTLS_ERR_NET_SEND_FAILED;
end;

function NetRecv (ctx : pointer; buf : pointer; len : size_t) : integer; cdecl;
var
  cl : TTCPSClient;
  count : integer;
  closed : boolean;
begin
//  Log ('net read ' + len.ToString);
  cl := TTCPSClient (ctx);
  closed := false;
  count := 0;
  if cl.ReadAvailable (buf, len, count, closed) then
    Result := count
  else if closed then
    Result := -MBEDTLS_ERR_NET_CONN_RESET
  else
    Result := -MBEDTLS_ERR_NET_RECV_FAILED;
end;

function GetTimer (ctx : pointer) : integer; cdecl;
var
  cl : TTCPSClient;
begin
  cl := TTCPSClient (ctx);
  // to be implemented
  Result := 0;
end;

procedure SetTimer (ctx : pointer; int_ms : uint32_t; fin_ms : uint32_t); cdecl;
var
  cl : TTCPSClient;
begin
  cl := TTCPSClient (ctx);
  // to be implemented
end;

procedure Debug (ctx : pointer; level : integer; file_ : PChar; line : integer; str : PChar); cdecl;
var
  cl : TTCPSClient;
begin
  cl := TTCPSClient (ctx);
  if Assigned (cl.OnDebug) then cl.OnDebug (cl, level, string (str));
  Log ('Debug ' + level.ToString + ' File ' + file_ + ' Line ' + Line.ToString + ' : ' + str);
end;

{ TTCPSReadThread }

constructor TTCPSReadThread.Create (anOwner : TTCPSClient);
begin
  inherited Create (true);
  Owner := anOwner;
  FreeOnTerminate := true;
  Start;
end;

procedure TTCPSReadThread.Execute;
var
  res : integer;
  len : integer;
  rxbuf : array [0..511] of char;
begin
//  Log ('Read Thread Started...');
  FillChar (rxbuf, sizeof (rxbuf), 0);
  len := sizeof (rxbuf);
  while not Terminated do
    begin
      res := mbedtls_ssl_read (@Owner.ssl, @rxbuf, len);
      if (res = -MBEDTLS_ERR_SSL_WANT_READ) or (res = -MBEDTLS_ERR_SSL_WANT_WRITE) then continue;
      if (res = -MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) or (res = -MBEDTLS_ERR_NET_CONN_RESET) then break; // read will terminate
      if res < 0 then  // general error
        begin
          log ('mbedtls_ssl_read error ' + ErrToStr (res));
          break; // read and socket will terminate
        end
      else
        begin
          if Assigned (Owner.OnAppRead) then Owner.OnAppRead (Owner, @rxbuf[0], res);
        end;
    end;
//  Log ('Read Thread Terminating');
  Owner.TidyUp;
end;

{ TTCPSClient }

procedure TTCPSClient.ReadThreadTerminated (Sender: TObject);
begin
  Log ('Read Thread Terminated.');
end;

constructor TTCPSClient.Create;
begin
  inherited Create;
  CipherVers := '';
  CipherSuite := '';
  Initialised := true;
  Seeded := false;
end;

destructor TTCPSClient.Destroy;
begin
  TidyUp;
  inherited Destroy;
end;

function TTCPSClient.Connect: boolean;
var
  res : integer;
  flags : Longword;
  allow : boolean;
  s : string;
begin
  Result := false;
  if Connected then exit;
  CipherVers := '';
  CipherSuite := '';
  if not Initialised then
    begin
      mbedtls_ssl_init (@ssl);
      mbedtls_ssl_config_init (@conf);
      mbedtls_x509_crt_init (@cacert);
    end;
  if not Seeded then Seed;
  res := mbedtls_ssl_config_defaults (@conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
  if res <> 0 then exit;
  mbedtls_ssl_conf_authmode (@conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain (@conf, @cacert, nil);
  mbedtls_ssl_conf_rng (@conf, mbedtls_ctr_drbg_random, @ctr_drbg);
  res := mbedtls_ssl_setup (@ssl, @conf);
  if res <> 0 then exit;
  if (HostName <> '') and (RemoteAddress = '') then
    begin
      s := ResolveHost (HostName);
      if s <> '' then RemoteAddress := s;
    end;
  if RemoteAddress = '' then exit;
  if HostName = '' then
    res := mbedtls_ssl_set_hostname (@ssl, PChar (RemoteAddress))
  else
    res := mbedtls_ssl_set_hostname (@ssl, PChar (HostName));
  if res <> 0 then exit;
  mbedtls_ssl_set_bio (@ssl, Self, @NetSend, @NetRecv, nil);
  Log ('Connecting to ' + RemoteAddress + ' .. ');
  Result := inherited Connect;
  if not Result then
    begin
      Log ('Connect Error ' + Winsock2ErrorToString (WSAGetLastError));
      exit;
    end;
  Result := false;
  res := mbedtls_ssl_handshake (@ssl);
  while res <> 0 do
    begin
      if (res <> -MBEDTLS_ERR_SSL_WANT_READ) and (res <> -MBEDTLS_ERR_SSL_WANT_WRITE) then exit;
      res := mbedtls_ssl_handshake (@ssl);
    end;
  CipherSuite := mbedtls_ssl_get_ciphersuite (@ssl);
  CipherVers := mbedtls_ssl_get_version (@ssl);
  if Assigned (FOnConnect) then FOnConnect (Self, CipherVers, CipherSuite);
  flags := mbedtls_ssl_get_verify_result (@ssl);
  allow := flags = 0;
  if Assigned (FOnVerify) then FOnVerify (Self, flags, allow);
  if not allow then
    begin
      AppClose;
      exit;
    end;
  ReadThread := TTCPSReadThread.Create (Self);  // start receive thread
  ReadThread.OnTerminate := ReadThreadTerminated;
  Result := true;
end;

procedure TTCPSClient.TidyUp;
begin
//  Log ('Tidy Up');
  CipherVers := '';
  CipherSuite := '';
  if Seeded then
    begin
      mbedtls_ctr_drbg_free (@ctr_drbg);
      Seeded:= false
    end;
  if Initialised then
    begin
      mbedtls_x509_crt_free (@cacert);
      mbedtls_ssl_config_free (@conf);
      mbedtls_ssl_free (@ssl);
      Initialised := false;
    end;
  if Connected then
    begin
      Disconnect;
    end;
  if Assigned (FOnDisconnect) then FOnDisconnect (Self);
end;

function TTCPSClient.Issues (code: Longword): TStringList;
var
  vrfy_buf : array [0..511] of char;
  s : string;
  i : integer;
begin
  Result := TStringList.Create;
  vrfy_buf[0] := #0;
  mbedtls_x509_crt_verify_info (vrfy_buf, sizeof (vrfy_buf), #10, code);
  s := vrfy_buf;
  i := Pos (#10, s);
  while i > 0 do
    begin
      if i > 1 then Result.Add (Copy (s, 1, i - 1));
      s := Copy (s, i + 1, length (s) - i);
      i := Pos (#10, s);
    end;
  if length (s) > 0 then Result.Add (s);
end;

procedure TTCPSClient.AppWrite (buf: pointer; len: cardinal);
var
  res : integer;
begin
  res := mbedtls_ssl_write (@ssl, buf, len);
  while res <= 0 do
    begin
      if (res <> -MBEDTLS_ERR_SSL_WANT_READ) and (res <> -MBEDTLS_ERR_SSL_WANT_WRITE) then
        begin
          Log ('ssl write failed ' + ErrToStr (res));
          break;
        end;
      res := mbedtls_ssl_write (@ssl, buf, len);
    end;
end;

procedure TTCPSClient.AppWrite (s: string);
begin
  AppWrite (@s[1], length (s));
end;

procedure TTCPSClient.AppClose;
begin
  mbedtls_ssl_close_notify (@ssl);
  TidyUp;
end;

procedure TTCPSClient.Seed;
var
  res : integer;
begin
  if Seeded then exit;
  pers := 'abcdef';
  mbedtls_ctr_drbg_init (@ctr_drbg);
  mbedtls_entropy_init (@entropy);
  mbedtls_entropy_add_source (@entropy, @RandomReadSource, nil, 0, MBEDTLS_ENTROPY_SOURCE_STRONG);
  mbedtls_entropy_add_source (@entropy, @RandomSource, nil, 0, MBEDTLS_ENTROPY_SOURCE_WEAK);
  res := mbedtls_ctr_drbg_seed (@ctr_drbg, mbedtls_entropy_func, @entropy, pers, 12);
  if res <> 0 then Log ('Seed Error ' + ErrToStr (Res));
  mbedtls_entropy_free (@entropy);
  Seeded := true;
end;

end.

