###############################################################################
# OpenVAS Vulnerability Test
#
# Drupal Multiple Vulnerabilities - August15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806103");
  script_version("2021-12-01T11:10:56+0000");
  script_cve_id("CVE-2015-6661", "CVE-2015-6660", "CVE-2015-6658");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-01 11:10:56 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2015-08-28 11:55:16 +0530 (Fri, 28 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Drupal Multiple Vulnerabilities - August15 (Windows)");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exixts as,

  - The Form API in the application does not properly validate the form token.

  - There is no restriction to get node titles by reading the menu.

  - Insufficient sanitization of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information, execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site and
  conduct CSRF attacks.");

  script_tag(name:"affected", value:"Drupal 6.x before 6.37 and 7.x before 7.39
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 6.37 or 7.39
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2015-003");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^[67]\.") {
  if(version_in_range(version:version, test_version:"6.0", test_version2:"6.36")) {
    fix = "6.37";
    VULN = TRUE;
  }

  if(version_in_range(version:version, test_version:"7.0", test_version2:"7.38")) {
    fix = "7.39";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);