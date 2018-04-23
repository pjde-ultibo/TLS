program CloudTest;

{$mode delphi}{$H+}
{$define use_tftp}

(*
  Test program for accessing a cloud based database

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
  Classes, Console, uLog, uTCPS,
  fpjson, jsonparser,
{$ifdef use_tftp}
  uTFTP, Winsock2,
{$endif}
  Ultibo, umbedTLS
  { Add additional units here };

const
  na : array [boolean] of string = ('NOT', '');
  api_key     = '5add1ddddddddddddddddddd'; // substitute with you own key
  account_url = 'xxxx-yyyy.restdb.io';      // substitute with account url
  table_name  = 'sensors';                  // substitute with own collection name

  JSONTypeNames : array [TJSONtype] of string =
    ('Unknown', 'Number', 'String', 'Boolean', 'Null', 'Array', 'Object');

type

  { THelper }

  THelper = class
    rx : TMemoryStream;
    Headers : TStringList;
    Decode : boolean;
    FRoot : TJSONData;
    ind : integer;
    function Indent : string;
    procedure ShowJSON (Data : TJSONData; n : string);
    procedure DoDebug (Sender : TObject; level : integer; s : string);
    procedure DoVerify (Sender : TObject; Flags : LongWord; var Allow : boolean);
    procedure DoAppRead (Sender : TObject; Buf : pointer; len : cardinal);
    procedure DoConnect (Sender : TObject; Vers, Suite : string);
    procedure DoDisconnect (Sender : TObject);
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
  Helper : THelper;

function display (s : string) : string; overload;
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

function display (s : TStream) : string; overload;
var
  ch : char;
begin
  s.Seek (0, soFromBeginning);
  Result := '';
  ch := #0;
  while s.Position < s.Size do
    begin
      s.Read (ch, 1);
      if ch in [' ' .. '~'] then
        Result := Result + ch
      else
        Result := Result + '<' + ord (ch).ToString + '>';
    end;
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

function THelper.Indent : string;
begin
  Result := Copy ('                                                               ', 1, ind);
end;

procedure THelper.ShowJSON (Data : TJSONData; n : string);
var
  i : integer;
  d : TJSONData;
  c : string;
begin
  if not Assigned (Data) then exit;
  c := Indent + n + ' (' + JSONTypeNames[Data.JSONType] + ')';
  case Data.JSONType of
    jtArray :
      begin
        Log (c);
        ind := ind + 2;
        for i := 0 to Data.Count - 1 do
          begin
            d := TJSONData (Data.Items[i]);
            ShowJSON (d, IntToStr (i))
         end;
        ind := ind - 2;
      end;
    jtObject :
      begin
        Log (c);
        ind := ind + 2;
        for i := 0 to Data.Count - 1 do
          begin
            d := TJSONData (Data.Items[i]);
            ShowJSON (d, TJSONObject (Data).Names[i]);
          end;
        ind := ind - 2;
      end;
    jtNull :
      begin
        c := c + ' = null';
        Log (c);
      end
    else
      begin
        c := c + ' = ' + Data.AsString;
        Log (c);
      end;
  end;
end;

procedure THelper.DoDebug (Sender: TObject; level: integer; s: string);
begin
  Log2 ('Do Debug ' + level.ToString + ' ' + s);
end;

procedure THelper.DoVerify (Sender: TObject; Flags: LongWord; var Allow: boolean);
var
  Reasons : TStringList;
  i : integer;
begin
  Log2 ('');
  Log2 ('Should ' + na[Allow] + ' Allow because :-');
  if Flags = 0 then
    Log ('  Certificate is good.')
  else
    begin
      Reasons := TTCPSClient (Sender).Issues (Flags);
      for i := 0 to Reasons.Count - 1 do Log2 ('  ' + Reasons[i]);
      Reasons.Free;
    end;
  Log2 ('');
  Allow := true;
end;

procedure THelper.DoAppRead (Sender: TObject; Buf: pointer; len: cardinal);
begin
 // Log ('Read ' + len.ToString + ' bytes.');
  if len <> 0 then rx.Write (Buf^, len);
end;

procedure THelper.DoConnect (Sender: TObject; Vers, Suite: string);
begin
  Log ('Connected - Vers : ' + Vers + ', Suite : ' + Suite);
end;

procedure THelper.DoDisconnect (Sender: TObject);
var
  ch : char;
  s : string;
  cr : boolean;
begin
  Log ('Disconnected...');
  if Decode then
    begin
      rx.Seek (0, soFromBeginning);
      s := '';
      cr := false;
      ch := #0;
      while rx.Position < rx.Size do
        begin
          rx.Read (ch, 1);
          if (ch = #10) and cr then
            begin
              if s = '' then
                begin
                  Log ('--------------------------------');
                  try
                    FRoot := GetJSON (rx, true);
                    ind := 0;
                    ShowJSON (FRoot, 'root');
                   // Log3 (FRoot.AsJSON); // reconsituted as JSON string
                    FRoot.Free;
                  except
                    on e : exception do Log (e.Message);
                  end;
                  break;
                end
              else
                begin
                  Log ('Hdr ' + s);
                  s := '';
                end;
            end
          else if (ch <> #10) and (ch <> #13) then
            s := s + ch;
          cr := ch = #13;
        end;
      rx.Clear;
    end
  else
    begin
      Log (display (rx));
      rx.Clear;
    end;
end;

constructor THelper.Create;
begin
  rx := TMemoryStream.Create;
  Headers := TStringList.Create;
end;

destructor THelper.Destroy;
begin
  rx.Free;
  Headers.Free;
  inherited Destroy;
end;

begin
  Console1 := ConsoleWindowCreate (ConsoleDeviceGetDefault, CONSOLE_POSITION_LEFT, true);
  Console2 := ConsoleWindowCreate (ConsoleDeviceGetDefault, CONSOLE_POSITION_TOPRIGHT, false);
  Console3 := ConsoleWindowCreate (ConsoleDeviceGetDefault, CONSOLE_POSITION_BOTTOMRIGHT, false);
  SetLogProc (@Log1);
  Log3 ('Cloud Database Test using TCPS and mbed TLS.');
  WaitForSDDrive;
  Log2 ('SD Drive ready.');
  Log2 ('');
  Log3 ('1 - Clear.');
  Log3 ('2 - Get Database.');
  Log3 ('3 - List Cipher suites.');
  Log3 ('');

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
  Helper := THelper.Create;
  aClient := TTCPSClient.Create;
  aClient.OnDebug := Helper.DoDebug;
  aClient.OnVerify := Helper.DoVerify;
  aClient.OnAppRead := Helper.DoAppRead;
  aClient.OnConnect := Helper.DoConnect;
  aclient.OnDisconnect := Helper.DoDisconnect;

  ch := #0;
  while true do
    begin
      if ConsoleGetKey (ch, nil) then
        case ch of
          '1' :
            begin
              ConsoleWindowClear (Console1);
            end;
          '2' :
            begin
              Helper.rx.Clear;
              Helper.Headers.Clear;
              Helper.Headers.Add ('Accept: */*');
              Helper.Headers.Add ('cache-control: no-cache');
              Helper.Headers.Add ('x-apikey: ' + api_key);
              Helper.Headers.Add ('Host: ' + account_url);
              Helper.Headers.Add ('content-type: application/json');
              Helper.Headers.Add ('Accept-Language: en');
              Helper.Decode := true;
              aClient.HostName := account_url;
              aClient.RemoteAddress := '';
              aClient.RemotePort := 443;
              if aClient.Connect then
                begin
                  t := 'GET /rest/' + table_name + ' HTTP/1.0'#13#10;
                  for i := 0 to Helper.Headers.Count - 1 do
                    t := t + Helper.Headers[i] + #13#10;
                  t := t + #13#10;
                  aClient.AppWrite (t);
                end;
            end;
          '3' :
            begin
              Log ('Cipher Suites..');
              p := mbedtls_ssl_list_ciphersuites;
              if p <> nil then
                while p^ <> 0 do
                  begin
                    x := mbedtls_ssl_get_ciphersuite_name (p^);
                    if x <> nil then Log ('Suite    ' + p^.ToHexString (8) + '    ' + string (x));
                    inc (p);
                  end;
            end;
          'Q', 'q' : break;
          end;
    end;
  aClient.Free;
  Helper.Free;
  ThreadHalt (0);
end.

