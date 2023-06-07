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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142320");
  script_version("2021-08-30T11:01:18+0000");
  script_tag(name:"last_modification", value:"2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-04-30 06:22:02 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 18:15:00 +0000 (Wed, 18 Dec 2019)");

  script_cve_id("CVE-2018-5743");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability (CVE-2018-5743) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability due to ineffective
  simultaneous TCP client limiting.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By design, BIND is intended to limit the number of TCP clients that can be
  connected at any given time. The number of allowed connections is a tunable parameter which, if unset, defaults
  to a conservative value for most servers. Unfortunately, the code which was intended to limit the number of
  simultaneous connections contains an error which can be exploited to grow the number of simultaneous connections
  beyond this limit.");

  script_tag(name:"impact", value:"By exploiting the failure to limit simultaneous TCP connections, an attacker
  can deliberately exhaust the pool of file descriptors available to named, potentially affecting network
  connections and the management of files such as log files or zone journal files.

  In cases where the named process is not limited by OS-enforced per-process limits, this could additionally
  potentially lead to exhaustion of all available free file descriptors on that system.");

  script_tag(name:"affected", value:"BIND 9.9.0 to 9.10.8-P1, 9.11.0 to 9.11.6, 9.12.0 to 9.12.4, 9.14.0. BIND 9
  Supported Preview Edition versions 9.9.3-S1 to 9.11.5-S3, and 9.11.5-S5. Versions 9.13.0 to 9.13.7 of the 9.13
  development branch.");

  script_tag(name:"solution", value:"Update to version 9.11.6-P1, 9.12.4-P1, 9.14.1, 9.11.5-S6, 9.11.6-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2018-5743");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "^9\.(9|10|11)\.[0-9]s[0-9]") {
  if (version_in_range(version: version, test_version: "9.9.3s1", test_version2: "9.11.5s5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.5-S6/9.11.6-S1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.9.0", test_version2: "9.11.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.6-P1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.12.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.12.4-P1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.13.0", test_version2: "9.13.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
