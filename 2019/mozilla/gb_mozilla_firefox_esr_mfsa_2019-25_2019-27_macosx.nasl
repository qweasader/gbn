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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815450");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-11735", "CVE-2019-11746", "CVE-2019-11744", "CVE-2019-11742",
                "CVE-2019-11747", "CVE-2019-11740", "CVE-2019-11752", "CVE-2019-9812",
                "CVE-2019-11743", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750",
                "CVE-2019-11738");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 19:51:00 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-09-05 13:26:16 +0530 (Thu, 05 Sep 2019)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2019-25_2019-27)-Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple use-after-free errors.

  - A same-origin policy violation.

  - Sandbox escape through Firefox Sync

  - Navigation events were not fully adhering to the W3C's 'Navigation-Timing Level 2'
    draft specification in some instances for the unload event.

  - Persistence of WebRTC permissions in a third party context.

  - A vulnerability exists in WebRTC where malicious web content can use probing
    techniques on the getUserMedia API using constraints.

  - A type confusion vulnerability exists in Spidermonkey.

  - 'Forget about this site' removes sites from pre-loaded HSTS list.

  - Content Security Policy (CSP) bypass.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  cause denial of service, escalate privileges, conduct cross site scripting
  attacks and disclose sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 68.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 68.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-26/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version: "68.0", test_version2: "68.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"68.1", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
