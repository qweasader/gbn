###############################################################################
# OpenVAS Vulnerability Test
#
# Apple QuickTime Multiple Vulnerabilities Mar14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804320");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-1243", "CVE-2014-1244", "CVE-2014-1245", "CVE-2014-1246",
                "CVE-2014-1247", "CVE-2014-1248", "CVE-2014-1249", "CVE-2014-1250",
                "CVE-2014-1251");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-03-04 09:38:28 +0530 (Tue, 04 Mar 2014)");
  script_name("Apple QuickTime Multiple Vulnerabilities Mar14 (Windows)");

  script_tag(name:"summary", value:"Apple QuickTime player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to:

  - An unspecified error when handling track lists.

  - Multiple boundary errors when handling H.264 encoded movie files, 'ftab'
  atoms, 'dref' atoms, 'ldat' atoms, PSD images, 'clef' atoms.

  - An unspecified error that is due to a signedness issue.

  - An out-of-bounds memory write error when handling 'ttfo' elements.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  conduct denial of service and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Apple QuickTime version before 7.7.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.7.5 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6151");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65786");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65787");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57148");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Feb/137");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.75.80.95")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.75.80.95", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
