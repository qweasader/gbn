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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148414");
  script_version("2022-07-18T10:11:09+0000");
  script_tag(name:"last_modification", value:"2022-07-18 10:11:09 +0000 (Mon, 18 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-08 02:57:13 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 15:36:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-2191");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (GHSA-8mpp-f3f7-xc28) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SslConnection does not release ByteBuffers in case of error
  code paths. For example, TLS handshakes that require client-auth with clients that send expired
  certificates will trigger a TLS handshake errors and the ByteBuffers used to process the TLS
  handshake will be leaked.");

  script_tag(name:"affected", value:"Eclipse Jetty version 10.0.9 and prior and version 11.0.x through
  11.0.9.");

  script_tag(name:"solution", value:"Update to version 10.0.10, 11.0.10 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-8mpp-f3f7-xc28");

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

if (version_is_less(version: version, test_version: "10.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
