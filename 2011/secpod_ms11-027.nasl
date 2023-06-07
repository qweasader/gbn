# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900281");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2010-0811", "CVE-2010-3973", "CVE-2011-1243", "CVE-2010-4588");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft IE Developer Tools WMITools and Windows Messenger ActiveX Control Vulnerability (2508272)");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15809/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40490");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45546");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47197");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64250");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-027");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"An unspecified error exists in the IE Developer Tools(iedvtool.dll), WMITools
  (WBEMSingleView.OCX) and Windows Messenger (msgsc.dll) ActiveX Controls when
  used with Internet Explorer. Attackers can execute arbitrary code by tricking
  a user into visiting a specially crafted web page.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-027.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  As a workaround set the killbit for the following CLSIDs:

  {1a6fe369-f28c-4ad9-a3e6-2bcb50807cf1}, {2745E5F5-D234-11D0-847A-00C04FD7BB08},
  {FB7199AB-79BF-11d2-8D94-0000F875C541}");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(hotfix_check_sp(win2k:5, xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2) <= 0){
  exit(0);
}

if(hotfix_missing(name:"2508272") == 0){
  exit(0);
}

## CLSID List
clsids = make_list(
  "{1a6fe369-f28c-4ad9-a3e6-2bcb50807cf1}",
  "{2745E5F5-D234-11D0-847A-00C04FD7BB08}",
  "{FB7199AB-79BF-11d2-8D94-0000F875C541}"
 );

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
