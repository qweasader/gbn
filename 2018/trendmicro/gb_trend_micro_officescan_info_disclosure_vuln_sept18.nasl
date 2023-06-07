###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro OfficeScan Information Disclosure Vulnerability Sep18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:trend_micro:office_scan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813924");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-15364");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-08 15:10:00 +0000 (Thu, 08 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-09-04 16:54:20 +0530 (Tue, 04 Sep 2018)");
  script_name("Trend Micro OfficeScan Information Disclosure Vulnerability (1120678)");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a named pipe request
  able to process out-of-bounds read.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan versions XG 12.0");

  script_tag(name:"solution", value:"Upgrade to Trend Micro OfficeScan versions
  XG SP1 CP 5180 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1120678");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

## XG SP1 CP 5180 = 12.0.5180
if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.0.5179")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"XG SP1 CP 5180", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
