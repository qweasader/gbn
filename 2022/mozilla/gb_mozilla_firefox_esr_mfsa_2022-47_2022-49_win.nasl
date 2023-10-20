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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826703");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406",
                "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410", "CVE-2022-45411",
                "CVE-2022-45421", "CVE-2022-45416", "CVE-2022-45418", "CVE-2022-45420");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 16:45:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-11-16 12:34:34 +0530 (Wed, 16 Nov 2022)");
  script_name("Mozilla Firefox ESR Security Update(mfsa_2022-47_2022-49)-Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Service Workers might have learned size of cross-origin media files.

  - Fullscreen notification bypass.

  - Use-after-free in InputStream implementation.

  - Use-after-free of a JavaScript Realm.

  - Fullscreen notification bypass via windowName.

  - Use-after-free in Garbage Collection.

  - ServiceWorker-intercepted requests bypassed SameSite cookie policy.

  - Cross-Site Tracing was possible via non-standard override headers.

  - Keystroke Side-Channel Leakage.

  - Custom mouse cursor could have been drawn over browser UI.

  - Iframe contents could be rendered outside the iframe.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service, disclose sensitive
  information and conduct spoofing on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  102.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade Mozilla Firefox ESR to version 102.5
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-48/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.5"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.5", install_path:path);
  security_message(data:report);
  exit(0);
}
