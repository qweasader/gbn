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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2015.133");
  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_tag(name:"creation_date", value:"2021-11-11 08:00:11 +0000 (Thu, 11 Nov 2021)");
  script_version("2021-11-15T10:47:05+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:47:05 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2015-133) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2015-133");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-133/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1192028");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1202868");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1205157");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NSS and NSPR memory corruption issues
Mozilla engineers Tyson Smith and David Keeler
reported a use-after-poison and buffer overflow in the ASN.1 decoder in Network Security
Services (NSS). These issues were in octet string parsing and were found through fuzzing
and code inspection. If these issues were triggered, they would lead to a potentially
exploitable crash. These issues were fixed in NSS version 3.19.2.1 and 3.19.4, shipped in
Firefox and Firefox ESR, respectively, as well as NSS 3.20.1.");

  script_tag(name:"affected", value:"Firefox version(s) below 42.");

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

if (version_is_less(version: version, test_version: "42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "42", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
