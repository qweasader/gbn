# Copyright (C) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814262");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-3144", "CVE-2018-3155", "CVE-2018-3171", "CVE-2018-3173",
                "CVE-2018-3277", "CVE-2018-3284", "CVE-2018-3283", "CVE-2018-3185",
                "CVE-2018-3187", "CVE-2018-3200", "CVE-2018-3162", "CVE-2018-3161");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-17 11:13:07 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Mysql Security Update (cpuoct2018 - 04) - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unspecified error within 'Server: Parser' component in MySQL Server.

  - An unspecified error within 'Server: Logging' component in MySQL Server.

  - Multiple unspecified errors within 'Server: Partition' component in MySQL
    Server.

  - An unspecified error within 'Server: Optimizer' component in MySQL Server.

  - Multiple unspecified errors within 'InnoDB' component in MySQL Server.

  - An unspecified error within 'Server: Security: Audit' component in MySQL
    Server.");

  script_tag(name:"impact", value:"Successful will allow remote attackers to
  have an impact on integrity and availability.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.7.x through 5.7.23,
  8.0.x through 8.0.12.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2018.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2018");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"5.7", test_version2:"5.7.23") ||
   version_in_range(version:vers, test_version:"8.0", test_version2:"8.0.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See reference", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);