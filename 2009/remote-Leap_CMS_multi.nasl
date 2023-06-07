# OpenVAS Vulnerability Test
# Description: This script multiple remote vulnerabilities on the Leap CMS
#
# remote-Leap_CMS_multi.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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

CPE = "cpe:/a:gowondesigns:leap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101026");
  script_version("2020-08-31T11:33:48+0000");
  script_cve_id("CVE-2009-1613", "CVE-2009-1614", "CVE-2009-1615");
  script_tag(name:"last_modification", value:"2020-08-31 11:33:48 +0000 (Mon, 31 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-04-30 23:55:19 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Leap CMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Web application abuses");
  script_dependencies("remote-detect-Leap_CMS.nasl");
  script_mandatory_keys("gowondesigns/leapcms/detected");

  script_tag(name:"solution", value:"For the sql injection vulnerability, set
  your php configuration to magic_quotes_gpc = off, for other vulnerabilities,
  it's recommended to download the latest stable version.");

  script_tag(name:"summary", value:"The remote Leap CMS is affected by multiple
  remote vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if(revcomp(a:vers, b:"0.1.4") <= 0) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See solution tag", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
