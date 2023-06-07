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
  script_oid("1.3.6.1.4.1.25623.1.0.900016");
  script_version("2022-07-06T10:11:12+0000");
  script_tag(name:"last_modification", value:"2022-07-06 10:11:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3364");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_name("Trend Micro OfficeScan ObjRemoveCtrl ActiveX Control BOF Vulnerability");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6152");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30407");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-07/0509.html");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to an ActiveX control buffer
  overflow vulnerability.");

  script_tag(name:"insight", value:"The flaws are due to an error in objRemoveCtrl control, which is used to display
  certain properties (eg., Server, ServerIniFile etc..) and their values when it is embedded
  in a web page. These property values can be overflowed to cause stack based overflow.");

  script_tag(name:"affected", value:"OfficeScan 7.3 build 1343 (Patch 4) and prior on Windows (All).

  Trend Micro Worry-Free Business Security (WFBS) version 5.0

  Trend Micro Client Server Messaging Security (CSM) versions 3.5 and 3.6");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to OfficeScan 10 or later.

  Quick Fix: Set killbits for the following clsid's
  {5EFE8CB1-D095-11D1-88FC-0080C859833B}");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to
  execute arbitrary code.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
scanVer = registry_get_sz(key:key, item:"Server_Version");
if(!scanVer)
  exit(0);

if(egrep(pattern:"^([0-6]\..*|7\.[0-2])$", string:scanVer)) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

if("7.3" >!< scanVer)
  exit(0);

scanPath = registry_get_sz(key:key, item:"Local_Path");
if(!scanPath)
  exit(0);

scanPath += "pccnt\PccNTRes.dll";

v = GetVersionFromFile(file:scanPath, verstr:"SpecialBuild", offset:-90000);

if(egrep(pattern:"^([0-9]?[0-9]?[0-9]|1[0-2][0-9][0-9]|13([0-3][0-9]|4[0-3]))$", string:v)) {
  clsid = "{5EFE8CB1-D095-11D1-88FC-0080C859833B}";
  clsidKey = "SOFTWARE\Classes\CLSID\"+ clsid;
  if(registry_key_exists(key:clsidKey)) {
    activeKey = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
    killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
    if(!killBit){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
