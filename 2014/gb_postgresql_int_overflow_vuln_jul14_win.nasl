###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Multiple Integer Overflow Vulnerabilities July14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804712");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-2669");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-07-07 15:46:46 +0530 (Mon, 07 Jul 2014)");
  script_name("PostgreSQL Multiple Integer Overflow Vulnerabilities July14 (Windows)");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple integer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an unspecified user-supplied input which is not properly
  validated.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to gain elevated privileges.");

  script_tag(name:"affected", value:"PostgreSQL version before 9.0.x before 9.0.16, 9.1.x before 9.1.12,
  9.2.x before 9.2.7, and 9.3.x before 9.3.3");

  script_tag(name:"solution", value:"Upgrade to version 9.3.3, 9.2.7, 9.1.12, and 9.0.16, or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66557");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91281");
  script_xref(name:"URL", value:"http://wiki.postgresql.org/wiki/20140220securityrelease");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

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

if(vers !~ "^9\.[0-3]\.")
  exit(99);

if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.0.15") ||
   version_in_range(version:vers, test_version:"9.1", test_version2:"9.1.11") ||
   version_in_range(version:vers, test_version:"9.2", test_version2:"9.2.6") ||
   version_in_range(version:vers, test_version:"9.3", test_version2:"9.3.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
