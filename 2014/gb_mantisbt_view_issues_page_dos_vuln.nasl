# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804650");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2013-1883");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-06-23 15:25:38 +0530 (Mon, 23 Jun 2014)");

  script_name("MantisBT 1.2.12 - 1.2.14 'View Issues' Page DoS Vulnerability");

  script_tag(name:"summary", value:"MantisBT is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the filter_api.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to consume all available
memory resources and cause a denial of service condition.");

  script_tag(name:"affected", value:"MantisBT version 1.2.12 through 1.2.14.");

  script_tag(name:"solution", value:"Update to version 1.2.15 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83347");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58626");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=15573");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_mandatory_keys("mantisbt/detected");

  script_tag(name:"solution_type", value:"VendorFix");

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

if (version_in_range(version: version, test_version: "1.2.12", test_version2: "1.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);