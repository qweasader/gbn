###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion 'XML External Entity' Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809027");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-4264");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:05:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-09-01 11:45:09 +0530 (Thu, 01 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion 'XML External Entity' Information Disclosure Vulnerability (APSB16-30)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in parsing
  crafted XML entities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information about the application.");

  script_tag(name:"affected", value:"ColdFusion 10 before Update 21 and
  11 before Update 10.");

  script_tag(name:"solution", value:"Upgrade to version 10 Update 21 or
  11 Update 10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb16-30.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92684");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("adobe/coldfusion/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+")) # nb: The HTTP Detection VT might only extract the major version like 11 or 2021
  exit(0);

version = infos["version"];
location = infos["location"];

## https://helpx.adobe.com/coldfusion/kb/coldfusion-10-updates.html
if(version_in_range(version:version, test_version:"10.0", test_version2:"10.0.20.299202")) {
  fix = "10.0.21.300068";
}

## https://helpx.adobe.com/coldfusion/kb/coldfusion-11-updates.html
else if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.09.299201")) {
  fix = "11.0.10.300066";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);