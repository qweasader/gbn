# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826488");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-39249", "CVE-2022-39250", "CVE-2022-39251", "CVE-2022-39236");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 15:35:00 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-30 12:15:00 +0530 (Fri, 30 Sep 2022)");
  script_name("Mozilla Thunderbird Security Update(mfsa2022-43) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the bugs in the
  matrix-js-sdk.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code and leak memory on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.3.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  102.3.1 or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-43");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.3.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.3.1", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);