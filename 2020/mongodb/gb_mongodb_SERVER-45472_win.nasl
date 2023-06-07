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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143870");
  script_version("2021-08-12T09:01:18+0000");
  script_tag(name:"last_modification", value:"2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-08 07:05:02 +0000 (Fri, 08 May 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-07 19:20:00 +0000 (Tue, 07 Jul 2020)");

  script_cve_id("CVE-2020-7921");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB 3.6 < 3.6.18, 4.0 < 4.0.15, 4.2 < 4.2.3, 4.3 < 4.3.3 Improper Serialization Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to an improper serialization vulnerability in the
  authorization subsystem.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper serialization of internal state in the authorization subsystem in
  MongoDB Server's authorization subsystem permits a user with valid credentials to bypass IP whitelisting
  protection mechanisms following administrative action.");

  script_tag(name:"affected", value:"MongoDB versions 3.6 prior to 3.6.18, 4.0 prior to 4.0.15, 4.2 prior to
  4.2.3 and 4.3 prior to 4.3.3.");

  script_tag(name:"solution", value:"Update to version 3.6.18, 4.0.15, 4.2.3, 4.3.3 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-45472");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.18");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.15");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2", test_version2: "4.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
