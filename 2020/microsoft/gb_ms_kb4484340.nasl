# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817408");
  script_version("2021-08-12T06:00:50+0000");
  script_cve_id("CVE-2020-1582");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 19:02:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 11:26:32 +0530 (Wed, 12 Aug 2020)");
  script_name("Microsoft Access 2016 Remote Code Execution Vulnerability (KB4484340)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4484340.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists in
  Microsoft Access because it fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system. An attacker could then install programs,
  view, change, or delete data or create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Access 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4484340");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Access/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

accVer = get_kb_item("SMB/Office/Access/Version");
if(!accVer){
  exit(0);
}

if(version_in_range(version:accVer, test_version:"16.0", test_version2:"16.0.5044.0999"))
{
  report = report_fixed_ver(file_checked:"msaccess.exe",
           file_version:accVer, vulnerable_range:"16.0 - 16.0.5044.0999");
  security_message(data:report);
  exit(0);
}
exit(0);
