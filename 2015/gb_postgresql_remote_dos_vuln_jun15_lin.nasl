###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Remote Denial Of Service Vulnerability June15 (Linux)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805805");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2015-3165");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-06-24 15:36:26 +0530 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Remote Denial Of Service Vulnerability June15 (Linux)");

  script_tag(name:"summary", value:"PostgreSQL is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is triggered when a timeout interrupt
  is fired partway through the session shutdown sequence.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to crash the program.");

  script_tag(name:"affected", value:"PostgreSQL version before 9.0.20, 9.1.x
  before 9.1.16, 9.2.x before 9.2.11, 9.3.x before 9.3.7, and 9.4.x before 9.4.2.");

  script_tag(name:"solution", value:"Upgrade to version 9.0.20, 9.1.16, 9.2.11,
  9.3.7, 9.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1587");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74787");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(version_is_less(version:vers, test_version:"9.0.20") ||
   version_in_range(version:vers, test_version:"9.1", test_version2:"9.1.15") ||
   version_in_range(version:vers, test_version:"9.2", test_version2:"9.2.10") ||
   version_in_range(version:vers, test_version:"9.3", test_version2:"9.3.6") ||
   version_in_range(version:vers, test_version:"9.4", test_version2:"9.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
