###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Word 2010 Service Pack 2 Multiple Vulnerabilities (KB4011270)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812204");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-11854");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-01 14:47:00 +0000 (Fri, 01 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-15 09:49:22 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Word 2010 Service Pack 2 Multiple Vulnerabilities (KB4011270)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011270");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Office software fails to properly handle objects in memory.

  - Missing security update in Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to run arbitrary
  code in the context of the current user and some unspecified impact.");

  script_tag(name:"affected", value:"Microsoft Word 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101746");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^14\." && version_is_less(version:exeVer, test_version:"14.0.7190.5000"))
{
  report = report_fixed_ver(file_checked:exePath + "winword.exe", file_version:exeVer, vulnerable_range:"14.0 - 14.0.7190.4999");
  security_message(data:report);
  exit(0);
}
exit(0);
