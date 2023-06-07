###############################################################################
# OpenVAS Vulnerability Test
#
# Drupal Multiple Vulnerabilities01- May16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808043");
  script_version("2021-12-01T11:10:56+0000");
  script_cve_id("CVE-2016-3171", "CVE-2016-3167", "CVE-2016-3165", "CVE-2016-3166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-01 11:10:56 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-09 17:46:00 +0000 (Mon, 09 May 2016)");
  script_tag(name:"creation_date", value:"2016-05-18 15:57:00 +0530 (Wed, 18 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Multiple Vulnerabilities01- May16 (Linux)");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exixts due to:

  - An error in session data truncation which can lead to unserialization of
    user provided data

  - The 'drupal_goto' function improperly decodes the contents of
    '$_REQUEST['destination']' before using it.

  - Form API ignores access restrictions on submit buttons.

  - An error in the 'drupal_set_header' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause remote code execution, initiate a redirect to an arbitrary
  external URL, bypass security restrictions and inject arbitrary HTTP
  headers.");

  script_tag(name:"affected", value:"Drupal 6.x before 6.38 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 6.38 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

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

if(version_in_range(version:version, test_version:"6.0", test_version2:"6.37")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.38", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);