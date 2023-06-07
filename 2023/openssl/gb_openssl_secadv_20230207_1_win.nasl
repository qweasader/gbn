# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104532");
  script_version("2023-02-08T10:20:24+0000");
  script_tag(name:"last_modification", value:"2023-02-08 10:20:24 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-08 08:09:35 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-4304", "CVE-2023-0215", "CVE-2023-0286");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL 1.0.2 < 1.0.2zg, 1.1.1 < 1.1.1t, 3.0 < 3.0.8 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-4304: Timing Oracle in RSA Decryption

  - CVE-2023-0215: Use-after-free following BIO_new_NDEF

  - CVE-2023-0286: X.400 address type confusion in X.509 GeneralName");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1 and 3.0.");

  script_tag(name:"solution", value:"Update to version 1.0.2zg, 1.1.1t, 3.0.8 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230207.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zg")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zg", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1t")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1t", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
