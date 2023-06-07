###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iCloud Security Updates (HT209451) - Windows
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814821");
  script_version("2021-10-07T07:48:17+0000");
  script_cve_id("CVE-2018-20346", "CVE-2018-20505", "CVE-2018-20506", "CVE-2019-6215",
                "CVE-2019-6212", "CVE-2019-6216", "CVE-2019-6217", "CVE-2019-6226",
                "CVE-2019-6227", "CVE-2019-6233", "CVE-2019-6234", "CVE-2019-6229");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-07 07:48:17 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-23 01:15:00 +0000 (Sun, 23 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-23 13:00:19 +0530 (Wed, 23 Jan 2019)");
  script_name("Apple iCloud Security Updates (HT209451) - Windows");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues exist in input validation and memory
    handling.

  - A type confusion issue and

  - A logic issue exists.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and conduct cross site scripting by
  processing maliciously crafted web content.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.10 on Windows.");

  script_tag(name:"solution", value:"Update to Apple iCloud 7.10 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209451");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# 7.10 => 7.10.0.9
if(version_is_less(version:vers, test_version:"7.10.0.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.10", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
