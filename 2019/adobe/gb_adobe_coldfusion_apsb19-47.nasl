# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:coldfusion";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815475");
  script_version("2021-08-30T14:01:20+0000");
  script_tag(name:"last_modification", value:"2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-09-26 10:37:29 +0530 (Thu, 26 Sep 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:21:00 +0000 (Fri, 04 Sep 2020)");

  script_cve_id("CVE-2019-8072", "CVE-2019-8073", "CVE-2019-8074");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB19-47)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("adobe/coldfusion/detected");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper validation of user supplied input, which allow command injection
    via vulnerable component.

  - An unknown security bypass error.

  - An unknown path traversal vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows attckers to
  disclose sensitive information, execute arbitrary code and bypass access control.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 2016, Update 11 and earlier versions
  and version 2018, Update 4 and earlier versions.");

  script_tag(name:"solution", value:"Update to version 2016 Update 12 or version
  2018 Update 5 respectively.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-47.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/coldfusion/kb/coldfusion-2016-update-12.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/coldfusion/kb/coldfusion-2018-update-5.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+")) # nb: The HTTP Detection VT might only extract the major version like 11 or 2021
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^2016\.0" && version_is_less(version: version, test_version: "2016.0.12.315717")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2016 Update 12", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version =~ "^2018\.0" && version_is_less(version: version, test_version: "2018.0.05.315699")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2018 Update 5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}
exit(99);
