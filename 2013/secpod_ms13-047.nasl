# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903309");
  script_version("2022-05-25T07:40:23+0000");
  script_cve_id("CVE-2013-3126", "CVE-2013-3110", "CVE-2013-3111", "CVE-2013-3112",
                "CVE-2013-3113", "CVE-2013-3114", "CVE-2013-3116", "CVE-2013-3117",
                "CVE-2013-3118", "CVE-2013-3119", "CVE-2013-3120", "CVE-2013-3121",
                "CVE-2013-3122", "CVE-2013-3123", "CVE-2013-3124", "CVE-2013-3125",
                "CVE-2013-3139", "CVE-2013-3141", "CVE-2013-3142");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2013-06-12 08:51:29 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2838727)");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60376");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60380");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60381");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60384");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60385");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60386");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60391");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60393");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to corrupt memory by the
  execution of arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x.");

  script_tag(name:"insight", value:"Multiple unspecified errors due to improper sanitation of user
  supplied input, when handling script debugging for a specially crafted webpage or when improperly
  accessing an object in memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-047.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3, win8:1) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer || ieVer !~ "^([6-9]|10)\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6391") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21336")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23500")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5161") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21336")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23500")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18836")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23108")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19436")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23500")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16489")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20599")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18155")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22325")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16489")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20599")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16613")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20718")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16611")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20716")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
