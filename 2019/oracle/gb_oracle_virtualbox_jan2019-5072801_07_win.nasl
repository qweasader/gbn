###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VirtualBox Security Updates (jan2019-5072801) 07 - Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814658");
  script_version("2022-08-31T10:10:28+0000");
  script_cve_id("CVE-2018-0734");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:41:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-01-16 15:28:33 +0530 (Wed, 16 Jan 2019)");
  script_name("Oracle VirtualBox Security Updates (jan2019-5072801) 07 - Windows");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to an unspecified security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  error in Core (OpenSSL) component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to affect confidentiality via unknown vectors.");

  script_tag(name:"affected", value:"VirtualBox versions Prior to 5.2.24
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox Prior to
  5.2.24 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
virtualVer = infos['version'];
path = infos['location'];

if(version_is_less(version:virtualVer, test_version:"5.2.24"))
{
  report = report_fixed_ver(installed_version:virtualVer, fixed_version:"5.2.24", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
