###############################################################################
# OpenVAS Vulnerability Test
#
# OCS Inventory NG < 2.5 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112351");
  script_version("2021-10-12T08:19:03+0000");
  script_tag(name:"last_modification", value:"2021-10-12 08:19:03 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2018-08-07 11:54:06 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-02 19:55:00 +0000 (Tue, 02 Oct 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-12482", "CVE-2018-12483", "CVE-2018-14473", "CVE-2018-14857");

  script_name("OCS Inventory NG < 2.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"https://www.tarlogic.com/en/blog/vulnerabilities-in-ocs-inventory-2-4-1/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Aug/6");

  script_tag(name:"summary", value:"OCS Inventory NG is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"OCS Inventory NG before version 2.5.");

  script_tag(name:"solution", value:"Update to version 2.5 or later.");

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

if (version_is_less(version: vers, test_version: "2.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);