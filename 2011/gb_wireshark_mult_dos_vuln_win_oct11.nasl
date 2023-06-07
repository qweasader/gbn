###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802248");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3482", "CVE-2011-3483", "CVE-2011-3484");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45927/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49522");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49524");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-16.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-14.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-12.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.6.x before 1.6.2.");
  script_tag(name:"insight", value:"- An error related to an uninitialised variable within the CSN.1 dissector
    can be exploited to cause a crash.

  - A buffer exception handling vulnerability exists that can allow denial of
    service attacks when processing certain malformed packets.

  - An error within the OpenSafety dissector can be exploited to cause a large
    loop and crash the application.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.2 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.1")) {
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.6.0 - 1.6.1");
  security_message(port: 0, data: report);
}
