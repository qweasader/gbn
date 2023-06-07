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
  script_oid("1.3.6.1.4.1.25623.1.0.902114");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0029", "CVE-2010-0030", "CVE-2010-0031", "CVE-2010-0032",
                "CVE-2010-0033", "CVE-2010-0034");
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (975416)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976881");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38099");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38107");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38108");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/973143");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0337");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-004");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious PPT file.");

  script_tag(name:"affected", value:"- Microsoft Office PowerPoint 2002 SP 3 and prior

  - Microsoft Office PowerPoint 2003 SP 3 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Buffer overflow error when handling file paths.

  - Heap overflow error when processing 'LinkedSlideAtom' records.

  - Array indexing error when processing 'OEPlaceholderAtom' records with a
    specially crafted 'placementId' field.

  - Use-after-free error when processing 'OEPlaceholderAtom' records.

  - Stack overflow error when processing 'TextBytesAtom' records.

  - Stack overflow error when processing 'TextCharsAtom' records.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-004.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-004");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^1[01]\.")
{
  pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
  if(pptVer && pptVer =~ "^1[01]\.")
  {
    if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6857") ||
       version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8317")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
