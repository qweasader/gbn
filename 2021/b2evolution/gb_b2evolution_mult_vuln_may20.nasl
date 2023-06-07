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

CPE = "cpe:/a:b2evolution:b2evolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145362");
  script_version("2021-08-24T09:01:06+0000");
  script_tag(name:"last_modification", value:"2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-02-11 06:11:41 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-17 20:24:00 +0000 (Wed, 17 Feb 2021)");

  script_cve_id("CVE-2020-22839", "CVE-2020-22840", "CVE-2020-22841");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("b2evolution < 6.11.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_b2evolution_detect.nasl");
  script_mandatory_keys("b2evolution/installed");

  script_tag(name:"summary", value:"b2evolution is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple XSS (CVE-2020-22839, CVE-2020-22841)

  - Open redirect (CVE-2020-22840)");

  script_tag(name:"affected", value:"b2evolution version 6.11.6 and prior.");

  script_tag(name:"solution", value:"Update to version 6.11.7 or later.");

  script_xref(name:"URL", value:"https://github.com/b2evolution/b2evolution/issues/102");
  script_xref(name:"URL", value:"https://sohambakore.medium.com/b2evolution-cms-reflected-xss-in-tab-type-parameter-in-evoadm-php-38886216cdd3");

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

if (version_is_less(version: version, test_version: "6.11.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.11.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
