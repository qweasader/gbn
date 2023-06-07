###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Dissector Multiple Vulnerabilities - March 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803331");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2479", "CVE-2013-2477",
                "CVE-2013-2476", "CVE-2013-2475");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-03-11 18:15:06 +0530 (Mon, 11 Mar 2013)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities - March 13 (Windows)");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58364");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028254");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a Denial of
  Service or to consume excessive CPU resources.");

  script_tag(name:"affected", value:"Wireshark versions 1.8.x before 1.8.6 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in RELOAD, MPLS Echo, CSN.1, HART/IP and TCP
  dissectors.");

  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.6 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");

if(sharkVer && sharkVer=~ "^1\.8")
{
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
