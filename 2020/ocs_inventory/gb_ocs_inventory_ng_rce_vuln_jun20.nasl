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

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144213");
  script_version("2021-08-16T09:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-07-03 07:08:57 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-13 21:15:00 +0000 (Mon, 13 Jul 2020)");

  script_cve_id("CVE-2020-14947");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OCS Inventory NG < 2.9 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_tag(name:"summary", value:"OCS Inventory NG is prone to an authenticated remote code
  execution (RCE) vulnerability.");

  script_tag(name:"insight", value:"OCS Inventory NG allows Remote Command Execution via shell metacharacters to
  require/commandLine/CommandLine.php because mib_file in plugins/main_sections/ms_config/ms_snmp_config.php is
  mishandled in get_mib_oid.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"OCS Inventory NG version 2.8 and prior.");

  script_tag(name:"solution", value:"Update to version 2.9 or later.");

  script_xref(name:"URL", value:"https://shells.systems/ocs-inventory-ng-v2-7-remote-command-execution-cve-2020-14947/");
  script_xref(name:"URL", value:"https://github.com/OCSInventory-NG/OCSInventory-ocsreports/releases/tag/2.9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "2.9")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
