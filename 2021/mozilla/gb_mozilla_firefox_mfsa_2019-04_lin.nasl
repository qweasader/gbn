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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.04");
  script_cve_id("CVE-2018-18356", "CVE-2018-18511", "CVE-2019-5785");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 15:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-04) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-04");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-04/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525433");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525817");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1526218");
  script_xref(name:"URL", value:"https://googleprojectzero.blogspot.com/2019/02/the-curious-case-of-convexity-confusion.html");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-18356: Use-after-free in Skia
A use-after-free vulnerability in the Skia library can occur when creating a path, leading to a potentially exploitable crash.

CVE-2019-5785: Integer overflow in Skia
An integer overflow vulnerability in the Skia library can occur after specific transform operations, leading to a potentially exploitable crash.

CVE-2018-18511: Cross-origin theft of images with ImageBitmapRenderingContext
Cross-origin images can be read from a canvas element in violation of the same-origin policy using the transferFromImageBitmap method. Note: This only affects Firefox 65. Previous versions are unaffected.");

  script_tag(name:"affected", value:"Firefox version(s) below 65.0.1.");

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

if (version_is_less(version: version, test_version: "65.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "65.0.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
