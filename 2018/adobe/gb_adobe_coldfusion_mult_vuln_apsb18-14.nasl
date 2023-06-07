###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion Multiple Vulnerabilities-APSB18-14
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813083");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-4938", "CVE-2018-4939", "CVE-2018-4940", "CVE-2018-4941",
                "CVE-2018-4942");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-15 14:51:00 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2018-04-12 12:11:00 +0530 (Thu, 12 Apr 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB18-14)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insecure library loading error.

  - Multiple input validation errors.

  - An unsafe XML parsing error.

  - The deserialization of untrusted data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application,
  disclose sensitive information and also to escalate privileges.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 11 before Update 14.");

  script_tag(name:"solution", value:"Upgrade Adobe ColdFusion 11 Update 14 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb18-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
path = infos["location"];

## https://helpx.adobe.com/coldfusion/kb/coldfusion-11-update-14.html
if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.14.307975")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"11.0.14.307976", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
