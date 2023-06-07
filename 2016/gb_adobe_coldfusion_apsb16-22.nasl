###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion Security Update APSB16-22
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808165");
  script_version("2021-09-17T13:01:55+0000");
  script_cve_id("CVE-2016-4159");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:09:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-06-16 12:39:02 +0530 (Thu, 16 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Security Update (APSB16-22)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to a reflected cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper input
  validation issue that could be used in reflected cross-site scripting
  attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"ColdFusion 10 before Update 20 and
  11 before Update 9.");

  script_tag(name:"solution", value:"Upgrade to version 10 Update 20 or
  11 Update 9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb16-22.html");

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

if(version_in_range(version:version, test_version:"10.0", test_version2:"10.0.20.299201")) {
  fix = "10.0.20.299202";
}

else if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.09.299200")) {
  fix = "11.0.09.299201";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);