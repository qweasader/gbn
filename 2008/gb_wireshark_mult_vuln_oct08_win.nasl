###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Vulnerabilities - Oct08 (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800040");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682",
                "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685");
  script_name("Wireshark Multiple Vulnerabilities - Oct08 (Windows)");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-06.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31838");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");

  script_tag(name:"impact", value:"Successful attacks may cause the application to crash via specially
  crafted packets.");

  script_tag(name:"affected", value:"Wireshark versions prior to 1.0.4 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  a. an error within the Bluetooth ACL dissector, PRP or MATE post dissector.
  Versions 0.99.2 through 1.0.3 are affected by this vulnerability.

  b. an error within the Q.931 dissector. Versions 0.10.3 through 1.0.3
  are affected by this vulnerability.

  c. an uninitialized data structures within the Bluetooth RFCOMM and USB
  Request Block (URB) dissector. Versions 0.99.7 through 1.0.3 are affected by this vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.4.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple security vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"0.99.2", test_version2:"1.0.3")) {
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"0.99.2 - 1.0.3");
  security_message(port: 0, data: report);
}
