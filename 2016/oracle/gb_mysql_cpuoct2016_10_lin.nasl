# Copyright (C) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809389");
  script_version("2021-10-13T11:01:26+0000");
  script_cve_id("CVE-2016-8288");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-13 11:01:26 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:03:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-10-19 15:54:26 +0530 (Wed, 19 Oct 2016)");
  script_name("Oracle MySQL Server 5.6 <= 5.6.30 / 5.7 <= 5.7.12 Security Update (cpuoct2016) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified vulnerability within the
  'Server: InnoDB' component.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will allow a remote
  authenticated user to partially modify data.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.6 through 5.6.30 and 5.7 through 5.7.12.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2016.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2016");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.30") ||
   version_in_range(version:vers, test_version:"5.7", test_version2:"5.7.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See the referenced vendor advisory", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);