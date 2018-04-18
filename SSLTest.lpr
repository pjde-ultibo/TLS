program SSLTest;

{$mode delphi}{$H+}
{$define use_tftp}

(*
  Test program for TCPSClient object

  pjde 2018

*)

{$hints off}
{$notes off}
uses
  RaspberryPi3,
  GlobalConfig,
  GlobalConst,
  GlobalTypes,
  Platform,
  Threads,
  SysUtils,
  Classes, Console, uLog, uFTP, uTCPS,
{$ifdef use_tftp}
  uTFTP, Winsock2,
{$endif}
  Ultibo, umbedTLS
  { Add additional units here };



const
  ny : array [boolean] of string = ('NOT', '');

type

  { THelper }

  THelper = class
    rx : string;

    procedure DoDebug (Sender : TObject; level : integer; s : string);
    procedure DoVerify (Sender : TObject; Flags : LongWord; var Allow : boolean);
    procedure DoAppRead (Sender : TObject; Buf : pointer; len : cardinal);
    constructor Create;
    destructor Destroy; override;
  end;

var
  Console1, Console2, Console3 : TWindowHandle;
  IPAddress : string;
  i : integer;
  p : Pinteger;
  s : array [0..255] of char;
  t : string;
  x : PChar;
  aClient : TTCPSClient;
  ch : char;
  FTPServer : TFTPServer;
  Helper : THelper;
  uc : TUserCred;
  HintsInfo : TAddrInfo;
  Info : PAddrInfo;

function display (s : string) : string;
var
  i : integer;
begin
  Result := '';
  for i := 1 to length (s) do
    if s[i] in [' ' .. '~'] then
      Result := Result + s[i]
    else
      Result := Result + '<' + ord (s[i]).ToString + '>';
end;

procedure Log1 (s : string);
begin
  ConsoleWindowWriteLn (Console1, s);
end;

procedure Log2 (s : string);
begin
  ConsoleWindowWriteLn (Console2, s);
end;

procedure Log3 (s : string);
begin
  ConsoleWindowWriteLn (Console3, s);
end;

procedure Msg2 (Sender : TObject; s : string);
begin
  Log2 ('TFTP - ' + s);
end;

{$ifdef use_tftp}
function WaitForIPComplete : string;
var
  TCP : TWinsock2TCPClient;
begin
  TCP := TWinsock2TCPClient.Create;
  Result := TCP.LocalAddress;
  if (Result = '') or (Result = '0.0.0.0') or (Result = '255.255.255.255') then
    begin
      while (Result = '') or (Result = '0.0.0.0') or (Result = '255.255.255.255') do
        begin
          sleep (1000);
          Result := TCP.LocalAddress;
        end;
    end;
  TCP.Free;
end;
{$endif}

procedure WaitForSDDrive;
begin
  while not DirectoryExists ('C:\') do sleep (500);
end;

{ THelper }

procedure THelper.DoDebug (Sender: TObject; level: integer; s: string);
begin
  Log2 ('Do Debug ' + level.ToString + ' ' + s);
end;

procedure THelper.DoVerify (Sender: TObject; Flags: LongWord; var Allow: boolean);
var
  Reasons : TStringList;
  i : integer;
begin
  Log2 ('Should ' + ny[Allow] + ' Allow because :-');
  if Flags = 0 then
    Log ('  Certificate is good.')
  else
    begin
      Reasons := TTCPSClient (Sender).Issues (Flags);
      for i := 0 to Reasons.Count - 1 do Log2 ('  ' + Reasons[i]);
      Reasons.Free;
    end;
  Allow := true;
end;

procedure THelper.DoAppRead (Sender: TObject; Buf: pointer; len: cardinal);
var
  i : integer;
begin
  if len = 0 then
    begin
      Log ('EOF.......................');
    end
  else
    begin

      i := length (rx);
      SetLength (rx, i + len);
      Move (Buf^, rx[i + 1], len);
      Log (display (rx));
      rx := '';

  (*    i := pos (#13#10, rx);
      while i > 0 do
        begin
          Log (Copy (rx, 1 , i - 1));
          rx := Copy (rx, i + 2, length (rx) - i);
          i := pos (#13#10, rx);
        end;   *)
    end;
end;

constructor THelper.Create;
begin
  rx := '';
end;

destructor THelper.Destroy;
begin
  inherited Destroy;
end;

begin
  Console1 := ConsoleWindowCreate (ConsoleDeviceGetDefault, CONSOLE_POSITION_LEFT, true);
  Console2 := ConsoleWindowCreate (ConsoleDeviceGetDefault, CONSOLE_POSITION_TOPRIGHT, false);
  Console3 := ConsoleWindowCreate (ConsoleDeviceGetDefault, CONSOLE_POSITION_BOTTOMRIGHT, false);
  SetLogProc (@Log1);
  Log3 ('mbed TLS Test.');
  WaitForSDDrive;
  Log3 ('SD Drive ready.');
{$ifdef use_tftp}
  IPAddress := WaitForIPComplete;
  Log3 ('Network ready. Local Address : ' + IPAddress + '.');
  Log3 ('');
  Log2 ('TFTP - Syntax "tftp -i ' + IPAddress + ' put kernel7.img"');
  SetOnMsg (@Msg2);
{$endif}
  i := mbedtls_version_get_number;
  Log3 ('Version No : ' + i.ToHexString (8));
  mbedtls_version_get_string (s);
  Log3 ('Version : ' + s);
  mbedtls_version_get_string_full (s);
  Log3 ('Version Full : ' + s);
  Log3 ('--------------------------------');
  FTPServer := TFTPServer.Create;
  // add user accounts and options
  uc := FTPServer.AddUser ('admin', 'admin', 'C:\');
  uc.Options := [foCanAddFolder, foCanChangeFolder, foCanDelete, foCanDeleteFolder, foRebootOnImg];
  uc := FTPServer.AddUser ('user', '', 'C:\');
  uc.Options := [foRebootOnImg];
  uc := FTPServer.AddUser ('anonymous', '', 'C:\');
  uc.Options := [foRebootOnImg];
  // use standard FTP port
  FTPServer.BoundPort := 21;
  // set it running
  FTPServer.Active := true;
  Helper := THelper.Create;
  aClient := TTCPSClient.Create;
  aClient.OnDebug := Helper.DoDebug;
  aClient.OnVerify := Helper.DoVerify;
  aClient.OnAppRead := Helper.DoAppRead;

  ch := #0;
  while true do
    begin
      if ConsoleGetKey (ch, nil) then
        case ch of
         '1' :
            begin
             end;
          '2' :
            begin
              if aClient <> nil then
                begin
                  aClient.RemoteAddress := '10.0.0.4';
                  aClient.RemotePort := 443;
                  Log ('Connect ' + ny[aClient.Connect]);
                end;
            end;
          '3' :
            begin
              if aClient <> nil then
                begin
                  aClient.Disconnect;
                  Log ('Disconnnected... ' + ny[not aClient.Connected]);
                end;

            end;
          '4' :
            if aClient <> nil then
              begin
                if aClient.Connected then
                  begin
                    t := 'GET /demo.html HTTP/1.0'#13#10#13#10;
                    aClient.AppWrite (@t[1], length (t));
                  end;
              end;
          '5' :
            begin

            end;
          'Q', 'q' : break;

          end;
    end;
  ThreadHalt (0);



{  Log (mbedtls_test_cas_pem_len.ToString);
pp := StrAlloc (mbedtls_test_cas_pem_len);
StrLCopy (pp, @mbedtls_test_cas_pem[0], mbedtls_test_cas_pem_len);
Log (pp);
StrDispose (pp);    }

(*
p := mbedtls_ssl_list_ciphersuites;
if p <> nil then
  while p^ <> 0 do
    begin
      x := mbedtls_ssl_get_ciphersuite_name (p^);
      if x = nil then
        Log ('Suite    ' + p^.ToHexString (8) + '    is nil')
      else
        Log ('Suite    ' + p^.ToHexString (8) + '    ' + string (x));
      inc (p);
    end;   *)



end.

