# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826597");
  script_version("2022-12-14T10:20:42+0000");
  script_cve_id("CVE-2022-42927", "CVE-2022-42928", "CVE-2022-42929", "CVE-2022-42930",
                "CVE-2022-42931", "CVE-2022-42932", "CVE-2022-46881", "CVE-2022-46885");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-14 10:20:42 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-10-19 17:19:22 +0530 (Wed, 19 Oct 2022)");
  script_name("Mozilla Firefox Security Update (MFSA2022-44) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Same-origin policy violation could have leaked cross-origin URLs.

  - Memory Corruption in JS Engine.

  - Denial of Service via window.print.

  - Race condition in DOM Workers.

  - Username saved to a plaintext file on disk.

  - Memory safety bugs.

  - Memory corruption in WebGL.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and disclose
  sensitive information on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  106 on Windows.");

  script_tag(name:"solution", value:"Update to version 106 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-44");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"106")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"106", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
