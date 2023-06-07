
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815542");
  script_version("2021-10-07T07:48:17+0000");
  script_cve_id("CVE-2019-8063", "CVE-2019-7957", "CVE-2019-7958", "CVE-2019-7959");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-07 07:48:17 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-08-14 17:30:01 +0530 (Wed, 14 Aug 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update APSB19-39 (Windows)");

  script_tag(name:"summary", value:"Adobe Creative cloud is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insecure transmission of sensitive data,

  - An insecure inherited permissions and

  - Using components with known vulnerabilities");


  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, leak the information, gain escalated privileges and
  cause the denial of service");

  script_tag(name:"affected", value:"Adobe Creative Cloud 4.6.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  4.9 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb19-39.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos['version'];
cloudPath = infos['location'];

if(version_is_less_equal(version:cloudVer, test_version:"4.6.1"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"4.9", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);
