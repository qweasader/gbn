###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Lucent/Ascend File Parser Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802844");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-2597");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-03 15:29:17 +0530 (Thu, 03 May 2012)");
  script_name("Wireshark Lucent/Ascend File Parser Denial of Service Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48506");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68335");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-09.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause the application to
  enter into an infinite loop and crash it.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.17, 1.4.0 to 1.4.7 and 1.6.0");
  script_tag(name:"insight", value:"The flaw is due to an error in Lucent/Ascend file parser when
  processing malicious packets.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.18 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

wireVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wireVer){
  exit(0);
}

if(version_in_range(version:wireVer, test_version:"1.2.0", test_version2:"1.2.17") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.7") ||
   version_is_equal(version:wireVer, test_version:"1.6.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
