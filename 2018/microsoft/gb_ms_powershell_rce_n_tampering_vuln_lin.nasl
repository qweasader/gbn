###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft PowerShell Core RCE and Tampering Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814182");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-8256", "CVE-2018-8415");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-11-15 11:09:36 +0530 (Thu, 15 Nov 2018)");
  script_name("Microsoft PowerShell Core 6.0 <= 6.0.4 / 6.1 Multiple Vulnerabilities - Linux");

  script_tag(name:"summary", value:"PowerShell Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists when PowerShell
  improperly handles specially crafted files.

  A tampering vulnerability exists in PowerShell that could allow an attacker to execute unlogged
  code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute malicious
  code on a vulnerable system and to bypass certain security restrictions and perform unauthorized
  actions.");

  script_tag(name:"affected", value:"PowerShell Core versions 6.0 to 6.0.4 and 6.1.");

  script_tag(name:"solution", value:"Update to version 6.0.5, 6.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.securitytracker.com/id/1042108");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/8");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/9");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_lin.nasl");
  script_mandatory_keys("PowerShell/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "6.1")
  fix = "6.1.1";

else if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.4"))
  fix = "6.0.5";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);