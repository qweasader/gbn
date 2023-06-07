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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148306");
  script_version("2022-07-01T10:11:09+0000");
  script_tag(name:"last_modification", value:"2022-07-01 10:11:09 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-06-23 03:30:01 +0000 (Thu, 23 Jun 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-29 18:30:00 +0000 (Wed, 29 Jun 2022)");

  script_cve_id("CVE-2022-2068");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: The c_rehash script allows command injection (CVE-2022-2068) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In addition to the c_rehash shell command injection identified
  in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise
  shell metacharacters to prevent command injection were found by code review.

  When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script
  where the file names of certificates being hashed were possibly passed to a command executed
  through the shell.

  This script is distributed by some operating systems in a manner where it is automatically
  executed. On such operating systems, an attacker could execute arbitrary commands with the
  privileges of the script.

  Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash
  command line tool.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1 and 3.0.");

  script_tag(name:"solution", value:"Update to version 1.0.2zf, 1.1.1p, 3.0.4 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220621.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zf")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zf", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1p")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1p", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);