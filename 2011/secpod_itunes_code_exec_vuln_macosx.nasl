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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902720");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple iTunes Arbitrary Code Execution Vulnerability (Mac OS X)");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_mandatory_keys("Apple/iTunes/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to lead to an
  unexpected application termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 10.2.2.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption issue in WebKit. A
  man-in-the-middle attack while browsing the iTunes Store via iTunes may lead to an unexpected
  application termination or arbitrary code execution.");

  script_tag(name:"solution", value:"Update to version 10.2.2 or later.");

  script_tag(name:"summary", value:"Apple iTunes is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Apr/msg00004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46849");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.2.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.2.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
