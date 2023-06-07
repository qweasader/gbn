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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900595");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2562");
  script_name("Wireshark AFS Dissector Denial of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35748");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1970");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-04.html");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 0.9.2 through 1.2.0 on Linux.");

  script_tag(name:"insight", value:"An unspecified error in the AFS dissector which can be exploited via unknown
  vectors.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.1 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_in_range(version:ver, test_version:"0.9.2", test_version2:"1.2.0")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.2.1");
  security_message(data:report);
  exit(0);
}

exit(99);
