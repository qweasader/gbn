# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117018");
  script_version("2020-11-10T06:17:23+0000");
  script_tag(name:"last_modification", value:"2020-11-10 06:17:23 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-06 10:48:39 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-14375", "CVE-2019-14376", "CVE-2019-14377");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpLDAPadmin < 1.2.5 Multiple XSS Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpldapadmin_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpldapadmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XSS in htdocs/create.php (CVE-2019-14377)

  - XSS in htdocs/password_checker.php (CVE-2019-14376)

  - XSS in htdocs/rename_form.php (CVE-2019-14375)");

  script_tag(name:"impact", value:"The flaw allows remote users to inject arbitrary
  web script or HTML.");

  script_tag(name:"affected", value:"phpLDAPadmin versions 1.2.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.5 or later.");

  script_xref(name:"URL", value:"https://github.com/leenooks/phpLDAPadmin/pull/82");

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

if (version_is_less(version: version, test_version: "1.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
