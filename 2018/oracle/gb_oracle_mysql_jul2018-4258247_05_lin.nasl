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
  script_oid("1.3.6.1.4.1.25623.1.0.813713");
  script_version("2022-07-20T10:33:02+0000");
  # nb: From the vendor advisory: The fix for CVE-2018-0739 also addresses CVE-2017-3737 and CVE-2017-3738.
  script_cve_id("CVE-2018-0739", "CVE-2018-3064", "CVE-2018-3062", "CVE-2017-3737", "CVE-2017-3738");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-18 18:55:00 +0000 (Mon, 18 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-07-18 12:35:29 +0530 (Wed, 18 Jul 2018)");
  script_name("Oracle MySQL Security Update (cpujul2018 - 05) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'InnoDB', 'Server: Installing (OpenSSL)' and 'Server: Memcached' components
  of MySQL Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on integrity and availability.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.6.40 and prior,
  5.7.22 and prior, 8.0.11 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2018.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2018");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
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

if(version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.40") ||
   version_in_range(version:vers, test_version:"5.7", test_version2:"5.7.22") ||
   version_in_range(version:vers, test_version:"8.0", test_version2:"8.0.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See reference", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);