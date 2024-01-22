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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142888");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-09-16 07:22:38 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_cve_id("CVE-2019-1547", "CVE-2019-1563");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL 1.0.2, 1.1.0, 1.1.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL is prone to multiple vulnerabilities:

  - ECDSA remote timing attack (CVE-2019-1547)

  - Padding Oracle in PKCS7_dataDecode and CMS_decrypt_set1_pkey (CVE-2019-1563)");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2 - 1.0.2s, 1.1.0 - 1.1.0k and 1.1.1 - 1.1.1c.");

  script_tag(name:"solution", value:"Update to version 1.0.2t, 1.1.0l, 1.1.1d or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20190910.txt");

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

if (version_in_range(version: version, test_version: "1.0.2", test_version2: "1.0.2s")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2t", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.0k")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.0l", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1d", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
