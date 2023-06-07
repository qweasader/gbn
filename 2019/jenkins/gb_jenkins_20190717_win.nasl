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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:jenkins:jenkins";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142680");
  script_version("2021-08-31T08:01:19+0000");
  script_tag(name:"last_modification", value:"2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-07-31 02:25:14 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 07:15:00 +0000 (Fri, 26 Jul 2019)");

  script_cve_id("CVE-2019-10352", "CVE-2019-10353", "CVE-2019-10354");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.186 and < 2.176.2 LTS Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Jenkins is prone to multiple vulnerabilities:

  - Arbitrary file write vulnerability using file parameter definitions (CVE-2019-10352)

  - CSRF protection tokens does not expire (CVE-2019-10353)

  - Unauthorized view fragment access (CVE-2019-10354)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Jenkins weekly up to and including 2.185 and Jenkins LTS up to and
  including 2.176.1");

  script_tag(name:"solution", value:"Update to version 2.176.2 LTS, 2.186 weekly or later.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2019-07-17/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less(version: version, test_version: "2.176.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.176.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.186")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.186", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
