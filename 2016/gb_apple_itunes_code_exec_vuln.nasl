###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Arbitrary Code Execution Vulnerability (Windows)
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810208");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-1742");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:06:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple iTunes Arbitrary Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"Apple iTunes is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a dynamic library
  loading issue in iTunes setup.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to local users to gain privileges via a Trojan horse DLL in the
  current working directory.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.4
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90688");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2016/May/msg00006.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# vulnerable versions, 12.4.0 == 12.4.0.119
if(version_is_less(version:vers, test_version:"12.4.0.119")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.4.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
