# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817976");
  script_version("2022-12-16T10:18:13+0000");
  script_cve_id("CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23983", "CVE-2021-23984",
                "CVE-2021-23985", "CVE-2021-23986", "CVE-2021-23987", "CVE-2021-23988",
                "CVE-2021-29955");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-16 10:18:13 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 14:15:00 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-03-26 15:51:21 +0530 (Fri, 26 Mar 2021)");
  script_name("Mozilla Firefox Security Update (MFSA 2021-10) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Texture upload into an unbound backing buffer resulted in an out-of-bound read.

  - Internal network hosts could have been probed by a malicious webpage.

  - Transitions for invalid ::marker properties resulted in memory corruption.

  - Malicious extensions could have spoofed popup information.

  - Devtools remote debugging feature could have been enabled without indication to the user.

  - A malicious extension could have performed credential-less same origin policy violations.

  - Memory safety bugs.

  - Transient Execution Vulnerability allowed leaking arbitrary memory address.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, cause denial of service and disclose sensitive
  information.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 87 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 87 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-10/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"87")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"87", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
