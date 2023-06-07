###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark MAC-LTE dissector Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802664");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-0444");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-30 17:17:17 +0530 (Mon, 30 Jul 2012)");
  script_name("Wireshark MAC-LTE dissector Buffer Overflow Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64624");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45775");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0079");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-02.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5530");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to create a denial of service
  or execute arbitrary code.");
  script_tag(name:"affected", value:"Wireshark versions 1.2.0 through 1.2.13 and 1.4.0 through 1.4.2 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error in the MAC-LTE dissector,
  which could be exploited to crash an affected application or compromise
  a vulnerable system.");
  script_tag(name:"solution", value:"Upgrade to the latest version of Wireshark 1.4.3 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

if(version_in_range (version:sharkVer, test_version:"1.2.0", test_version2:"1.2.13") ||
   version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.2")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
