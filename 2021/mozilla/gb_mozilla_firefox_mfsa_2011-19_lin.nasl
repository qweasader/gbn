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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2011.19");
  script_cve_id("CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376");
  script_tag(name:"creation_date", value:"2021-11-16 11:08:07 +0000 (Tue, 16 Nov 2021)");
  script_version("2021-12-09T10:59:33+0000");
  script_tag(name:"last_modification", value:"2021-12-09 10:59:33 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2011-19) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2011-19");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-19/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=642734,642338,639648,646662,645572,629858,626262,643051");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=648705,643927,654015,653238,653026,652401,643839,597162,648022");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=650874,635235");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=651990");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=655742");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Miscellaneous memory safety hazards (rv:3.0/1.9.2.18)
Mozilla developers identified and fixed several memory safety bugs
in the browser engine used in Firefox and other Mozilla-based
products. Some of these bugs showed evidence of memory corruption
under certain circumstances, and we presume that with enough effort at
least some of these could be exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 3.6.18 and below 5.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.6.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.18", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}
if (version_in_range_exclusive(version: version, test_version_lo: "4", test_version_up: "5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
