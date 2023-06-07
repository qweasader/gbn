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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148255");
  script_version("2022-06-17T03:04:02+0000");
  script_tag(name:"last_modification", value:"2022-06-17 03:04:02 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-10 05:08:20 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-15 21:13:00 +0000 (Wed, 15 Jun 2022)");

  script_cve_id("CVE-2022-30522");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.53 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If Apache HTTP Server 2.4.53 is configured to do
  transformations with mod_sed in contexts where the input to mod_sed may be very large, mod_sed
  may make excessively large memory allocations and trigger an abort.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.53.");

  script_tag(name:"solution", value:"Update to version 2.4.54 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.54");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "2.4.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
