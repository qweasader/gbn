# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142400");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-05-13 09:38:08 +0000 (Mon, 13 May 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 15:49:00 +0000 (Mon, 30 Jan 2023)");

  script_cve_id("CVE-2019-2693", "CVE-2019-2694", "CVE-2019-2695", "CVE-2019-2692", "CVE-2019-2630",
                "CVE-2019-2634", "CVE-2019-2580", "CVE-2019-2585", "CVE-2019-2593", "CVE-2019-2624",
                "CVE-2019-2626", "CVE-2019-2644", "CVE-2019-2631", "CVE-2019-2596", "CVE-2019-2607",
                "CVE-2019-2625", "CVE-2019-2681", "CVE-2019-2685", "CVE-2019-2686", "CVE-2019-2687",
                "CVE-2019-2688", "CVE-2019-2689", "CVE-2019-2587", "CVE-2019-2635", "CVE-2019-2584",
                "CVE-2019-2589", "CVE-2019-2606", "CVE-2019-2620", "CVE-2019-2691", "CVE-2019-2636",
                "CVE-2019-2617");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 <= 8.0.15 Security Update (cpuapr2019) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The attacks range in variety and difficulty. Most of them allow an attacker
  with network access via multiple protocols to compromise the MySQL Server.

  For further information refer to the official advisory via the referenced link.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 8.0 through 8.0.15.");

  script_tag(name:"solution", value:"Update to version 8.0.16 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2019.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuapr2019");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.16", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);