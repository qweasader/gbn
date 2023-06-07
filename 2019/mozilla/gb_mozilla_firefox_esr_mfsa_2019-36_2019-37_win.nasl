# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815728");
  script_version("2021-09-08T09:01:34+0000");
  script_cve_id("CVE-2019-17008", "CVE-2019-13722", "CVE-2019-11745", "CVE-2019-17009",
                "CVE-2019-17010", "CVE-2019-17005", "CVE-2019-17011", "CVE-2019-17012");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-16 19:15:00 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-12-04 15:57:35 +0530 (Wed, 04 Dec 2019)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2019-36_2019-37) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A use-after-free issue in worker destruction.

  - A stack corruption issue due to incorrect number of arguments in WebRTC code.

  - An out of bounds write issue in NSS when encrypting with a block cipher.

  - Unprivileged processes can access updater temporary files.

  - A use-after-free issue when performing device orientation checks.

  - A buffer overflow issue in plain text serializer.

  - A use-after-free issue when retrieving a document in antitracking.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, gain access to sensitive
  information and conduct denial of service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 68.3 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox ESR version 68.3
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-37/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"68.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"68.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);