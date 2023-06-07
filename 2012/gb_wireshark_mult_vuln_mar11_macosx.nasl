###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Vulnerabilities March-11 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802901");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-0713", "CVE-2011-1139");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-06-27 15:20:54 +0530 (Wed, 27 Jun 2012)");
  script_name("Wireshark Multiple Vulnerabilities March-11 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46626");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65460");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-04.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.15.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to overflow a buffer and
  execute arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 through 1.2.14
  Wireshark version 1.4.0 through 1.4.3 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - Improper bounds checking by the Visual C++ analyzer.

  - Error in 'wiretap/pcapng.c', which allows remote attackers to cause a
    denial of service via a pcap-ng file that contains a large packet-length
    field.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.4  or 1.2.15 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.2.0", test_version2:"1.2.14")||
   version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
