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

CPE = "cpe:/a:prestashop:prestashop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144416");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2020-08-19 04:58:25 +0000 (Wed, 19 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-23 19:08:00 +0000 (Thu, 23 Apr 2020)");

  script_cve_id("CVE-2020-5270", "CVE-2020-5285");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PrestaShop 1.7.6.0 < 1.7.6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_http_detect.nasl");
  script_mandatory_keys("prestashop/detected");

  script_tag(name:"summary", value:"PrestaShop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-5270: Open redirection when using back parameter

  - CVE-2020-5285: Reflected XSS with back parameter");

  script_tag(name:"affected", value:"PrestaShop versions 1.7.6.0 through 1.7.6.4.");

  script_tag(name:"solution", value:"Update to version 1.7.6.5 or later.");

  script_xref(name:"URL", value:"https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-375w-q56h-h7qc");
  script_xref(name:"URL", value:"https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-j3r6-33hf-m8wh");

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

if (version_in_range(version: version, test_version: "1.7.6.0", test_version2: "1.7.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
