# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900061");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4264", "CVE-2008-4265", "CVE-2008-4266");
  script_name("Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (959070)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32622");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Successful exploitation could execute arbitrary code on the remote system
  and corrupt memory via a specially crafted Excel Spreadsheet (XLS) file.");

  script_tag(name:"affected", value:"Microsoft Windows 2K/XP/2003.");

  script_tag(name:"insight", value:"The flaws are due to

  - an error while validating an index value in a NAME record.

  - an error in the processing of Excel records.

  - an error in the processing of Excel formula.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-074.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^(9|1[0-2])\.")
{
  excelVer = get_kb_item("SMB/Office/Excel/Version");
  if(!excelVer || excelVer !~ "^(9|1[0-2])\."){
    exit(0);
  }

  if(version_in_range(version:excelVer, test_version:"9.0", test_version2:"9.0.0.8973")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6849")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8236")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6331.4999")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
