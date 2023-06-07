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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147911");
  script_version("2022-04-13T03:04:01+0000");
  script_tag(name:"last_modification", value:"2022-04-13 03:04:01 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-05 02:33:07 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-11 19:39:00 +0000 (Mon, 11 Apr 2022)");

  script_cve_id("CVE-2022-1121", "CVE-2022-1120", "CVE-2022-1099", "CVE-2022-1157");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab < 14.7.7, 14.8.x < 14.8.5, 14.9.x < 14.9.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-1121: GitLab Pages uses default (disabled) server Timeouts and a weak TCP Keep-Alive
  timeout

  - CVE-2022-1120: Incorrect include in pipeline definition exposes masked CI variables in UI

  - CVE-2022-1099: Absence of limit for the number of tags that can be added to a runner can cause
  performance issues

  - CVE-2022-1157: Redact InvalidURIError error messages");

  script_tag(name:"affected", value:"GitLab prior to version 14.7.7, version 14.8.x prior to 14.8.5
  and 14.9.x prior to 14.9.2.");

  script_tag(name:"solution", value:"Update to version 14.7.7, 14.8.5, 14.9.2 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/03/31/critical-security-release-gitlab-14-9-2-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "14.7.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.7.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.8.0", test_version_up: "14.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.9.0", test_version_up: "14.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
