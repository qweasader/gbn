###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Dissector Multiple Vulnerabilities - May 13 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803621");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3562", "CVE-2013-3561", "CVE-2013-3560", "CVE-2013-3559",
                "CVE-2013-3558", "CVE-2013-3555");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-05-28 15:42:11 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities - May 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59992");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59994");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59996");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59998");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60003");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.7.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash the
  application, resulting in denial of service condition.");
  script_tag(name:"affected", value:"Wireshark versions 1.8.x before 1.8.7 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to errors in Websocket, MySQL, ETCH, MPEG DSM-CC,
  DCP ETSI, PPP CCP and GTPv2 dissectors.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.7 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(sharkVer && sharkVer=~ "^1\.8")
{
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.6")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
