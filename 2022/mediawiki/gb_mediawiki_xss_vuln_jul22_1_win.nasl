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
  script_oid("1.3.6.1.4.1.25623.1.0.124098");
  script_version("2022-07-14T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-14 10:10:42 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-06 10:28:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-12 19:22:00 +0000 (Tue, 12 Jul 2022)");

  script_cve_id("CVE-2022-34911");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.7, 1.36.x < 1.37.3, 1.38.x < 1.38.1 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS can occur in configurations that allow a JavaScript
  payload in a username. After account creation, when it sets the page title to 'Welcome' followed
  by the username, the username is not escaped.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.7, version 1.36.x through
  1.37.2 and 1.38.0.");

  script_tag(name:"solution", value:"Update to version 1.35.7, 1.37.3, 1.38.1 or later.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T308471");

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

if (version_is_less(version:version, test_version:"1.35.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.35.7", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.36.0", test_version_up: "1.37.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.38.0", test_version_up: "1.38.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.38.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
