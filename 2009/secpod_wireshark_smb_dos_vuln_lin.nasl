# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:wireshark:wireshark';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900991");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4377");
  script_name("Wireshark SMB Dissectors Denial of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37407");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3596");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-09.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4301");
  script_xref(name:"URL", value:"http://www.wireshark.org/download/automated/captures/fuzz-2009-12-07-11141.pcap");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to trick the user to render the
  crafted malicious capture packet thus causing Denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 0.9.0 to 1.2.4 on Linux.");

  script_tag(name:"insight", value:"Error occurs in the SMB and SMB2 dissectors while processing malformed
  packets.");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.2.5.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:ver, test_version:"0.9.0", test_version2:"1.2.4")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.2.5");
  security_message(data:report);
  exit(0);
}

exit(99);
