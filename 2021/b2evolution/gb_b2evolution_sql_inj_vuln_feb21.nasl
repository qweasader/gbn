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
  script_oid("1.3.6.1.4.1.25623.1.0.145775");
  script_version("2021-08-24T09:01:06+0000");
  script_tag(name:"last_modification", value:"2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-04-19 03:41:27 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 18:50:00 +0000 (Fri, 04 Jun 2021)");

  script_cve_id("CVE-2021-28242");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("b2evolution < 7.2.3 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_b2evolution_detect.nasl");
  script_mandatory_keys("b2evolution/installed");

  script_tag(name:"summary", value:"b2evolution is prone to an SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SQL Injection in the 'evoadm.php' component of b2evolution allows remote
  attackers to obtain sensitive database information by injecting SQL commands into the 'cf_name' parameter
  when creating a new filter under the 'Collections' tab.");

  script_tag(name:"affected", value:"b2evolution version 7.2.2 and probably prior.");

  script_tag(name:"solution", value:"Update to version 7.2.3 or later.");

  script_xref(name:"URL", value:"https://github.com/b2evolution/b2evolution/issues/109");
  script_xref(name:"URL", value:"https://deadsh0t.medium.com/authenticated-boolean-based-blind-error-based-sql-injection-b752225f0644");

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

if (version_is_less(version: version, test_version: "7.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
