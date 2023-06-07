###############################################################################
# OpenVAS Vulnerability Test
#
# Apple QuickTime Multiple Vulnerabilities Jan16 (Windows)
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

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806963");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2015-7117", "CVE-2015-7092", "CVE-2015-7091", "CVE-2015-7090",
                "CVE-2015-7089", "CVE-2015-7088", "CVE-2015-7087", "CVE-2015-7086",
                "CVE-2015-7085", "CVE-2017-2218");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:22:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-18 10:15:22 +0530 (Mon, 18 Jan 2016)");
  script_name("Apple QuickTime Multiple Vulnerabilities Jan16 (Windows)");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple memory
  corruption issues and an issue in the installer of QuickTime with the
  DLL search path.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have unexpected application termination or arbitrary code
  execution with the privilege of the user invoking the installer.");

  script_tag(name:"affected", value:"Apple QuickTime version before 7.7.9 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.7.9
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80170");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN94771799/index.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2016/Jan/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"7.79.80.95")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.7.9 (7.79.80.95)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
