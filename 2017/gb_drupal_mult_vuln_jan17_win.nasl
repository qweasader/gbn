###############################################################################
# OpenVAS Vulnerability Test
#
# Drupal Multiple Vulnerabilities Jan17 (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108100");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-6377", "CVE-2017-6379", "CVE-2017-6381");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-17 11:54:37 +0100 (Fri, 17 Mar 2017)");
  script_name("Drupal Multiple Vulnerabilities (SA-2017-001) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-2017-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96919");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Editor module incorrectly checks access to inline private files.

  - Some admin paths were not protected with a CSRF token.

  - A 3rd party development library including with Drupal 8 development
  dependencies is vulnerable to remote code execution.");

  script_tag(name:"impact", value:"An attacker can exploit these issues
  to bypass certain security restrictions, perform unauthorized actions,
  and execute arbitrary code. Failed exploit attempts may result in a
  denial of service condition.");

  script_tag(name:"affected", value:"Drupal core 8.x versions prior to 8.2.7");

  script_tag(name:"solution", value:"Upgrade to version 8.2.7 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if(version_in_range(version:version, test_version:"8.0", test_version2:"8.2.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.2.7", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);