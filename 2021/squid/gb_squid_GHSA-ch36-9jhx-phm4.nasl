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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146030");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2021-05-28 03:54:10 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_cve_id("CVE-2021-28651");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid 2.0 < 4.14, 5.0.1 < 5.0.5 DoS Vulnerability (SQUID-2021:1)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability in
  the URN processing.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to a buffer management bug Squid is vulnerable to a DoS
  attack against the server it is operating on.

  This attack is limited to proxies which attempt to resolve a 'urn:' resource identifier. Support
  for this resolving is enabled by default in all Squid.

  This problem allows a malicious server in collaboration with a trusted client to consume
  arbitrarily large amounts of memory on the server running Squid.

  Lack of available memory resources impacts all services on the machine running Squid. Once
  initiated the DoS situation will persist until Squid is shutdown.");

  script_tag(name:"affected", value:"Squid version 2.0 through 4.14 and 5.0.1 through 5.0.5.");

  script_tag(name:"solution", value:"Update to version 4.15, 5.0.6 or later. See the referenced vendor
  advisory for a workaround.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-ch36-9jhx-phm4");

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

if (version_in_range(version: version, test_version: "2.0", test_version2: "4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.1", test_version2: "5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
