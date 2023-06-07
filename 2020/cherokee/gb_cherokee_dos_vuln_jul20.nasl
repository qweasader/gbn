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

CPE = "cpe:/a:cherokee-project:cherokee";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144328");
  script_version("2021-08-16T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-07-29 06:26:54 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-23 22:15:00 +0000 (Wed, 23 Dec 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-12845");

  script_name("Cherokee Web Server 0.4.27 <= 1.2.104 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_cherokee_http_detect.nasl");
  script_mandatory_keys("cherokee/detected");

  script_tag(name:"summary", value:"Cherokee Web Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cherokee is affected by a denial of service due to NULL pointer dereferences.
  A remote unauthenticated attacker can crash the server by sending an HTTP request to protected resources using a
  malformed Authorization header that is mishandled during a cherokee_buffer_add call within
  cherokee_validator_parse_basic or cherokee_validator_parse_digest.");

  script_tag(name:"impact", value:"An unauthenticated attacker may crash the server.");

  script_tag(name:"affected", value:"Cherokee Web Server through versions 0.4.27 to 1.2.104.");

  script_tag(name:"solution", value:"Apply the provided patch in the linked github.com pull
  request or update to a later version including this patch once released.");

  script_xref(name:"URL", value:"https://github.com/cherokee/webserver/issues/1242");
  script_xref(name:"URL", value:"https://github.com/cherokee/webserver/pull/1243");

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

if (version_in_range(version: version, test_version: "0.4.27", test_version2: "1.2.104")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
