# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.818038");
  script_version("2021-08-25T14:01:09+0000");
  script_cve_id("CVE-2021-28454", "CVE-2021-28456", "CVE-2021-28449");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 22:21:00 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-15 12:22:32 +0530 (Thu, 15 Apr 2021)");
  script_name("Microsoft Excel 2010 Service Pack 2 Multiple Vulnerabilities (KB3017810)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3017810");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper input
  validation in Microsoft Office software.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and gain sensitive information on the affected systems.");

  script_tag(name:"affected", value:"Microsoft Excel 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3017810");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");

  exit(0);
}
include("host_details.inc");
include("version_func.inc");

vers = get_kb_item("SMB/Office/Excel/Version");
if(!vers){
  exit(0);
}

path = get_kb_item("SMB/Office/Excel/Install/Path");
if(!path){
  path = "Unable to fetch the install path";
}

if(version_in_range(version:vers, test_version:"14.0", test_version2:"14.0.7268.4999"))
{
  report = report_fixed_ver(file_checked:path + "Excel.exe",
                            file_version:vers, vulnerable_range:"14.0 - 14.0.7268.4999");
  security_message(data:report);
  exit(0);
}
exit(99);
