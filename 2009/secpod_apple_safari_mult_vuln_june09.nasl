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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900723");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0162");
  script_name("Apple Safari Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34925");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1298");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/May/msg00000.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/May/msg00001.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"affected", value:"Apple Safari version prior to 3.2.3 and 4 Beta on Windows.");

  script_tag(name:"insight", value:"Browser faces input validation error while handing 'feed:' protocol based
  URLs which causes injection of arbitrary codes.");

  script_tag(name:"solution", value:"Upgrade to Safari version 3.2.3 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes and can
  cause XSS, Buffer Overflow, JavaScript code injection and denial of service in the context of an affected system.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.525.29.0") ||
   version_in_range(version:vers, test_version:"4.0", test_version2:"4.28.17.0")) { # 4 Beta range
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 3.2.3 (3.525.29.0) or 4.0 Final", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
