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

CPE = "cpe:/a:microsoft:asp.net_core" ;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815126");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-0820", "CVE-2019-0980", "CVE-2019-0981");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 13:29:00 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 11:38:35 +0530 (Thu, 16 May 2019)");
  script_name(".NET Core Multiple DoS Vulnerabilities-01 (May 2019)");

  script_tag(name:"summary", value:"ASP.NET Core is prone to multiple DoS vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An error when .NET Core improperly process RegEx strings.

  - Multiple errors when .NET Core improperly handle web requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct DoS condition.");

  script_tag(name:"affected", value:"ASP.NET Core 1.0.x prior to version 1.0.16
  and 1.1.x prior to version 1.1.13");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core 1.0.16 or 1.1.13 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108245");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0980");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0981");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/1.0/1.0.16/1.0.16.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.13/1.1.13.md");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if(coreVers =~ "^1\.0" && version_is_less(version:coreVers, test_version:"1.0.16")){
  fix = "1.0.16";
}

else if (coreVers =~ "^1\.1" && version_is_less(version:coreVers, test_version:"1.1.13")){
  fix = "1.1.13";
}

if(fix)
{
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
