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
  script_oid("1.3.6.1.4.1.25623.1.0.143027");
  script_version("2021-09-08T08:01:40+0000");
  script_tag(name:"last_modification", value:"2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-10-23 05:18:34 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-11 20:15:00 +0000 (Mon, 11 Nov 2019)");

  script_cve_id("CVE-2019-3011", "CVE-2019-2966", "CVE-2019-2967", "CVE-2019-3004", "CVE-2019-2991",
                "CVE-2019-2963", "CVE-2019-2968", "CVE-2019-2997", "CVE-2019-2982", "CVE-2019-2998",
                "CVE-2019-2957", "CVE-2019-3018", "CVE-2019-3009");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 <= 8.0.17 Security Update (cpuoct2019) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Oracle MySQL Server is prone to multiple vulnerabilities.

  For further information refer to the official advisory via the referenced link.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 8.0 through 8.0.17.");

  script_tag(name:"solution", value:"Update to version 8.0.18 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2019.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2019");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.18", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);