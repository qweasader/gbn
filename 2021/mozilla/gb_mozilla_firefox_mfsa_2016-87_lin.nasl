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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2016.87");
  script_cve_id("CVE-2016-5287", "CVE-2016-5288");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2022-02-23T10:17:11+0000");
  script_tag(name:"last_modification", value:"2022-02-23 10:17:11 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 16:29:00 +0000 (Mon, 30 Jul 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2016-87) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2016-87");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-87/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1309823");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1310183");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-5287: Crash in nsTArray_base<T>::SwapArrayElements
A potentially exploitable use-after-free crash during actor destruction with service workers. This issue does not affect releases earlier than Firefox 49.

CVE-2016-5288: Web content can read cache entries
A Cliqz.com developer demonstrated that web content could access information in the HTTP cache if e10s is disabled. This can reveal some visited URLs and the contents of those pages. This issue affects Firefox 48 and 49.");

  script_tag(name:"affected", value:"Firefox version(s) below 49.0.2.");

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

if (version_is_less(version: version, test_version: "49.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "49.0.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
