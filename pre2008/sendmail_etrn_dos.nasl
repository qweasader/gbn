# OpenVAS Vulnerability Test
# Description: Sendmail ETRN command DOS
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11350");
  script_version("2022-05-12T09:32:01+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/904");
  script_cve_id("CVE-1999-1109");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sendmail ETRN command DOS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_tag(name:"solution", value:"Install sendmail version 8.10.1 and higher, or
  install a vendor supplied patch.");

  script_tag(name:"summary", value:"The remote sendmail server, according to its version number,
  allows remote attackers to cause a denial of service by sending a series of ETRN commands then
  disconnecting from the server, while Sendmail continues to process the commands
  after the connection has been terminated.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

# nb: 8.10.0 and previous
if(vers =~ "^8\.([0-9]|[0-9]\.[0-9]+|10\.0)$") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.10.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);