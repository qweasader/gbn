# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808157");
  script_version("2021-10-14T12:01:33+0000");
  script_cve_id("CVE-2016-2831", "CVE-2016-2828", "CVE-2016-2826", "CVE-2016-2824",
                "CVE-2016-2822", "CVE-2016-2821", "CVE-2016-2819", "CVE-2016-2818");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-14 12:01:33 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:04:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-06-08 11:15:18 +0530 (Wed, 08 Jun 2016)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2016-49_2016-61) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper handling of paired fullscreen and pointerlock requests in
    combination with closing windows.

  - The use of a texture after its recycle pool has been destroyed during
    WebGL operations.

  - The files extracted by the updater from a MAR archive are not locked
    for writing and can be overwritten by other processes while the updater
    is running.

  - An improper size checking while writing to an array during some WebGL
    shader operations.

  - A use-after-free in contenteditable mode.

  - An improper parsing of HTML5 fragments in a foreign context.

  - The memory safety bugs in the browser engine.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers  to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR versions before 45.2.");

  script_tag(name:"solution", value:"Update to version 45.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-58/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-56/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-55/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-53/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-52/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-51/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-50/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-49/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"45.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);