# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902217");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-14 10:07:03 +0200 (Wed, 14 Jul 2010)");
  script_cve_id("CVE-2010-0266");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Outlook SMB Attachment Remote Code Execution Vulnerability (978212)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41446");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-045");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Outlook/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code by sending a specially crafted email attachment to an affected system.");

  script_tag(name:"affected", value:"Microsoft Office Outlook 2002/2003/2007.");

  script_tag(name:"insight", value:"The flaw is caused by an error when processing file attachments which are
  attached using the 'ATTACH_BY_REFERENCE' value of the 'PR_ATTACH_METHOD'
  property.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-045.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

outVer = get_kb_item("SMB/Office/Outlook/Version");
if(outVer)
{
  if(version_in_range(version:outVer, test_version:"10.0", test_version2:"10.0.6862") ||
     version_in_range(version:outVer, test_version:"11.0", test_version2:"11.0.8324") ||
     version_in_range(version:outVer, test_version:"12.0", test_version2:"12.0.6535.5004")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
