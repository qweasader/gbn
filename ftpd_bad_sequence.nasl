# SPDX-FileCopyrightText: 2008 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80063");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("FTP server accepts a bad sequence of commands");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2008 Michel Arboi");
  script_dependencies("find_service_3digits.nasl", "logins.nasl", "ftpd_no_cmd.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"insight", value:"The remote server advertises itself as being a FTP server, but it accepts
  commands sent in bad order, which indicates that it may be a backdoor or a proxy.

  Further FTP tests on this port will be disabled to avoid false alerts.");

  script_tag(name:"summary", value:"The remote FTP service accepts commands in any order.");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");
include("ftp_func.inc");

function test(soc, port) {

  local_var soc, port;
  local_var r, score;

  score = 0;
  r = ftp_recv_line(socket:soc, retry:2);
  if(!r) {
    ## set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
    set_kb_item(name:"ftp/" + port + "/no_banner", value:TRUE);
    return NULL;
  }

  if(r =~ '^[45][0-9][0-9] ' ||
     match(string:r, pattern:'Access denied*', icase:TRUE)) {
    set_kb_item(name:"ftp/" + port + "/denied", value:TRUE);
    return NULL;
  }

  vt_strings = get_vt_strings();

  send(socket:soc, data:'PASS ' + vt_strings["default_rand"] + '\r\n');
  r = ftp_recv_line(socket:soc, retry:2);
  if(r =~ '^230[ -]') { # USER logged in
    set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
    score ++;
  }

  send(socket:soc, data:'USER ' + vt_strings["default_rand"] + '\r\n');
  r = ftp_recv_line(socket:soc, retry:2);
  if(r !~ '^331[ -]')
    return score;

  send(socket:soc, data:'QUIT\r\n');
  r = ftp_recv_line(socket:soc, retry:2);
  if(!r)
    return score;

  send(socket:soc, data:'QUIT\r\n');
  r2 = ftp_recv_line(socket:soc, retry:2);
  if(r =~ '^221[ -]' && r2 =~ '^221[ -]') {
    score ++;
  }
  return score;
}

port = ftp_get_port(default:21);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

score = test(soc:soc, port:port);

if(score >= 1) {
  log_message(port:port);
  set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
}

ftp_close(socket:soc);
