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

CPE = "cpe:/a:apache:tapestry";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148458");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-07-14 07:37:12 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 10:31:00 +0000 (Thu, 21 Jul 2022)");

  script_cve_id("CVE-2022-31781");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tapestry < 5.8.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tapestry_http_detect.nasl");
  script_mandatory_keys("apache/tapestry/detected");

  script_tag(name:"summary", value:"Apache Tapestry is prone to a regular expression denial of
  service (ReDoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Tapestry is vulnerable to regular expression denial of
  service (ReDoS) in the way it handles Content Types. Specially crafted Content Types may cause
  catastrophic backtracking, taking exponential time to complete.

  Specifically, this is about the regular expression used on the parameter of the
  org.apache.tapestry5.http.ContentType class.");

  script_tag(name:"affected", value:"Apache Tapestry version 5.8.1 and prior.");

  script_tag(name:"solution", value:"Update to version 5.8.2 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/07/12/3");

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

if (version_is_less(version: version, test_version: "5.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
