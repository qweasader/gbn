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
  script_oid("1.3.6.1.4.1.25623.1.0.902721");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-2698");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark ANSI A MAP Files Denial of Service Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_family("Denial of Service");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash an affected application,
  denying service to legitimate users.");
  script_tag(name:"affected", value:"Wireshark version 1.6.0
  Wireshark version 1.4.x through 1.4.7");
  script_tag(name:"insight", value:"The flaw is caused to an infinite loop was found in the way ANSI A Interface
  dissector of the Wireshark network traffic analyser processed certain ANSI A
  MAP capture files. If Wireshark read a malformed packet off a network or
  opened a malicious packet capture file, it could lead to denial of service.");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.4.8 or 1.6.1 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49071");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/07/20/2");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=37930");
  exit(0);
}

include("version_func.inc");

wireVer = get_kb_item("Wireshark/Win/Ver");
if(!wireVer){
  exit(0);
}

if(version_is_equal(version:wireVer, test_version:"1.6.0") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
