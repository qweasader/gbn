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

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113945");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-04-25 12:30:46 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-02 16:26:00 +0000 (Mon, 02 May 2022)");

  script_cve_id("CVE-2021-22570", "CVE-2022-21457", "CVE-2022-21425", "CVE-2022-21440",
                "CVE-2022-21459", "CVE-2022-21478", "CVE-2022-21479", "CVE-2022-21418",
                "CVE-2022-21413", "CVE-2022-21412", "CVE-2022-21414", "CVE-2022-21435",
                "CVE-2022-21436", "CVE-2022-21437", "CVE-2022-21438", "CVE-2022-21452",
                "CVE-2022-21462", "CVE-2022-21415", "CVE-2022-21423");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 <= 8.0.28 Security Update (cpuapr2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.0 through 8.0.28.");

  script_tag(name:"solution", value:"Update to version 8.0.29 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2022.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuapr2022");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
