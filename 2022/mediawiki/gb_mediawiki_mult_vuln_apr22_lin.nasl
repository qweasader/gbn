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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147929");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-04-06 03:55:15 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 18:09:00 +0000 (Wed, 21 Sep 2022)");

  script_cve_id("CVE-2022-28201", "CVE-2022-28202", "CVE-2022-28203");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.6, 1.36.0 < 1.36.4, 1.37.0 < 1.37.2 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-28201: Title::newMainPage() goes into an infinite recursion loop if it points to a
  local interwiki

  - CVE-2022-28202: Messages widthheight/widthheightpage/nbytes not escaped when used in galleries
  or Special:RevisionDelete

  - CVE-2022-28203: Requesting Special:NewFiles on a wiki with many file uploads with actor as a
  condition can result in a DoS");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.6, version 1.36.x through
  1.36.3 and 1.37.x through 1.37.1.");

  script_tag(name:"solution", value:"Update to version 1.35.6, 1.36.4, 1.37.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/YJNXKPV5Z56NSUQ4G3SXPDUIZG5EQ7UR/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T297571");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T297543");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T297731");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.35.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.36.0", test_version_up: "1.36.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.37.0", test_version_up: "1.37.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
