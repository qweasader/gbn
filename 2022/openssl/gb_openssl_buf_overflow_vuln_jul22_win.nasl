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
  script_oid("1.3.6.1.4.1.25623.1.0.148377");
  script_version("2022-07-14T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-14 10:10:42 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 04:07:40 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-12 17:05:00 +0000 (Tue, 12 Jul 2022)");

  script_cve_id("CVE-2022-2274");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Heap memory corruption with RSA private key operation (CVE-2022-2274) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a buffer overflow vulnerability in the RSA
  implementation for AVX512IFMA capable CPUs.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The OpenSSL 3.0.4 release introduced a serious bug in the RSA
  implementation for X86_64 CPUs supporting the AVX512IFMA instructions. This issue makes the RSA
  implementation with 2048 bit private keys incorrect on such machines and memory corruption will
  happen during the computation. As a consequence of the memory corruption an attacker may be able
  to trigger a remote code execution on the machine performing the computation. SSL/TLS servers or
  other servers using 2048 bit RSA private keys running on machines supporting AVX512IFMA
  instructions of the X86_64 architecture are affected by this issue.");

  script_tag(name:"affected", value:"OpenSSL version 3.0.4.");

  script_tag(name:"solution", value:"Update to version 3.0.5 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220705.txt");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/issues/18625");

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

if (version_is_equal(version: version, test_version: "3.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
