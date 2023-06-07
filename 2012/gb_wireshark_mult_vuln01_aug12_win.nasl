###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Vulnerabilities(01) - August 2012 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802945");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4298", "CVE-2012-4295", "CVE-2012-4294", "CVE-2012-4287",
                "CVE-2012-4286");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-21 14:03:40 +0530 (Tue, 21 Aug 2012)");
  script_name("Wireshark Multiple Vulnerabilities(01) - August 2012 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50276/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55035");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027404");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-25.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-16.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-14.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  in the context of the application, crash affected application or to consume
  excessive CPU resources.");
  script_tag(name:"affected", value:"Wireshark 1.8.x before 1.8.2 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - An error within the pcap-ng file parser, Ixia IxVeriWave file parser and
    ERF dissector can be exploited to cause a buffer overflow.

  - An error within the MongoDB dissector can be exploited to trigger an
    infinite loop and consume excessive CPU resources.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.2 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.1")) {
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.8.0 - 1.8.1");
  security_message(port:0, data:report);
}
