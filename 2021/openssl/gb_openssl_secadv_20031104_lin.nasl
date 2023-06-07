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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112920");
  script_version("2021-08-30T10:29:27+0000");
  script_tag(name:"last_modification", value:"2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2003-0851");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Denial of Service in ASN.1 parsing (CVE-2003-0851) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in OpenSSL would cause certain ASN.1 sequences to trigger
  a large recursion. On platforms such as Windows this large recursion cannot be handled correctly
  and so the bug causes OpenSSL to crash.");

  script_tag(name:"impact", value:"A remote attacker could exploit this flaw if they can
  send arbitrary ASN.1 sequences which would cause OpenSSL to crash. This could be performed for
  example by sending a client certificate to a SSL/TLS enabled server which is configured to accept
  them.");

  script_tag(name:"affected", value:"OpenSSL 0.9.6k.");

  script_tag(name:"solution", value:"Update to version 0.9.6l or later. See the references for
  more details.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20031104.txt");

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

if (version_is_equal(version: version, test_version: "0.9.6k")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.6l", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
