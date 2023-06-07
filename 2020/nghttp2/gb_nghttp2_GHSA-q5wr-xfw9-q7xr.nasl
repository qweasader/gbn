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

CPE = "cpe:/a:nghttp2:nghttp2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144089");
  script_version("2021-08-16T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-06-09 04:40:06 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-11080");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nghttp2 < 1.41.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_nghttp2_detect.nasl");
  script_mandatory_keys("nghttp2/detected");

  script_tag(name:"summary", value:"nghttpd2 is prone to a denial of service vulnerability due to when
  receiving an overly large HTTP/2 SETTINGS frame payload.");

  script_tag(name:"insight", value:"The proof of concept attack involves a malicious client constructing a
  SETTINGS frame with a length of 14400 bytes (2400 individual settings entries) over and over again. The
  attack causes the CPU to spike at 100%.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nghttpd2 versions prior to 1.41.0.");

  script_tag(name:"solution", value:"Update to version 1.41.0 or later.");

  script_xref(name:"URL", value:"https://github.com/nghttp2/nghttp2/security/advisories/GHSA-q5wr-xfw9-q7xr");

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

if (version_is_less(version: version, test_version: "1.41.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.41.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
