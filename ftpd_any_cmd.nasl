# SPDX-FileCopyrightText: 2008 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80062");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Fake FTP server accepts any command");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Service detection");
  script_copyright("Copyright (C) 2008 Michel Arboi");
  script_dependencies("find_service_3digits.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"insight", value:"The remote server advertises itself as being a FTP server, but it accepts
  any command, which indicates that it may be a backdoor or a proxy.

  Further FTP tests on this port will be disabled to avoid false alerts.");

  script_tag(name:"summary", value:"The remote FTP service is not working properly");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("ftp_func.inc");

global_var ftpcmd;
ftpcmd["CWD"]=1;  ftpcmd["XCWD"]=1; ftpcmd["CDUP"]=1; ftpcmd["XCUP"]=1;
ftpcmd["SMNT"]=1; ftpcmd["QUIT"]=1; ftpcmd["PORT"]=1; ftpcmd["PASV"]=1;
ftpcmd["EPRT"]=1; ftpcmd["EPSV"]=1; ftpcmd["ALLO"]=1; ftpcmd["RNFR"]=1;
ftpcmd["RNTO"]=1; ftpcmd["DELE"]=1; ftpcmd["MDTM"]=1; ftpcmd["RMD"]=1;
ftpcmd["XRMD"]=1; ftpcmd["MKD"]=1;  ftpcmd["XMKD"]=1; ftpcmd["PWD"]=1;
ftpcmd["XPWD"]=1; ftpcmd["SIZE"]=1; ftpcmd["SYST"]=1; ftpcmd["HELP"]=1;
ftpcmd["NOOP"]=1; ftpcmd["FEAT"]=1; ftpcmd["OPTS"]=1; ftpcmd["AUTH"]=1;
ftpcmd["CCC"]=1;  ftpcmd["CONF"]=1; ftpcmd["ENC"]=1;  ftpcmd["MIC"]=1;
ftpcmd["PBSZ"]=1; ftpcmd["PROT"]=1; ftpcmd["TYPE"]=1; ftpcmd["STRU"]=1;
ftpcmd["MODE"]=1; ftpcmd["RETR"]=1; ftpcmd["STOR"]=1; ftpcmd["STOU"]=1;
ftpcmd["APPE"]=1; ftpcmd["REST"]=1; ftpcmd["ABOR"]=1; ftpcmd["USER"]=1;
ftpcmd["PASS"]=1; ftpcmd["ACCT"]=1; ftpcmd["REIN"]=1; ftpcmd["LIST"]=1;

function test(port, login, pass) {

  local_var port, login, pass;
  local_var soc, r, cmd, answer;

  soc = open_sock_tcp(port);
  if(!soc)
    return NULL;

  r = ftp_recv_line(socket:soc, retry:2);
  if(!r) {
    debug_print('No FTP welcome banner on port ', port, '\n');
    # set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
    set_kb_item(name:"ftp/" + port + "/no_banner", value:TRUE);
    ftp_close(socket:soc);
    return NULL;
  }
  debug_print(level:2, 'Banner = ', r);

  if(r =~ '^[45][0-9][0-9] ' || match(string:r, pattern:'Access denied*', icase:TRUE)) {
    debug_print('FTP server on port ', port, ' is closed\n');
    set_kb_item(name:"ftp/" + port + "/denied", value:TRUE);
    ftp_close(socket:soc);
    return NULL;
  }

  send(socket:soc, data:"USER " + login + '\r\n');
  r = ftp_recv_line(socket:soc, retry:2);
  if(r !~ "^230") { # USER logged in
    send(socket:soc, data:"PASS " + pass + '\r\n');
    r = ftp_recv_line(socket:soc, retry:2);
    if(r !~ "2[0-9][0-9] ") {
      debug_print('Cannot login to FTP server on port ', port, '. Provide a valid account!\n');
      set_kb_item(name:"ftp/" + port + "/denied", value:TRUE);
      ftp_close(socket:soc);
      return NULL;
    }
  }

  repeat
    cmd = rand_str(length:4, charset:'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  until(!ftpcmd[cmd]);

  send(socket:soc, data:cmd + '\r\n');
  r = ftp_recv_line(socket:soc, retry:2);
  if(!r)
    answer = " doesn't answer";
  else
    answer = ' answers "' + substr(r, 0, 2) + '"';

  ftp_close(socket:soc);
  debug_print(level:2, 'FTP server on port ', port, answer, ' to command ', cmd, '\n');
  if(strlen(r) == 0 || r =~ '^5[0-9][0-9]')
    return 0;
  debug_print('FTP server on port ', port, ' accepts command ', cmd, '\n');
  return 1;
}

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

port = ftp_get_port(default:21);

ok = 0;
miserable_failure = 0;
for(i = 0; i < 5; i ++) {
  z = test(port:port, login:login, pass:pass);
  if(isnull(z)) {
    if(miserable_failure ++ > 1) {
      debug_print(miserable_failure, ' miserables failures! Exiting\n');
      exit(0);
    }
  }

  if(z) {
    if(++ok > 2) {
      log_message(port:port);
      set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
      exit(0);
    }
  }
}

exit(99);
