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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818957");
  script_version("2022-01-17T03:04:33+0000");
  script_cve_id("CVE-2022-21842");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-17 03:04:33 +0000 (Mon, 17 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 16:45:00 +0000 (Fri, 14 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 09:31:05 +0530 (Thu, 13 Jan 2022)");
  script_name("Microsoft Word 2016 RCE Vulnerability (KB5002057)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002057");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the presence of
  an error when a maliciously modified file is opened.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Word 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002057");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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
if(!exeVer)
  exit(0);

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath)
  exePath = "Unable to fetch the install path";

if(exeVer =~ "^16\." && version_is_less(version:exeVer, test_version:"16.0.5266.1000")) {
  report = report_fixed_ver(file_checked:exePath + "winword.exe",
                            file_version:exeVer, vulnerable_range:"16.0 - 16.0.5266.0999");
  security_message(data:report);
  exit(0);
}

exit(99);
