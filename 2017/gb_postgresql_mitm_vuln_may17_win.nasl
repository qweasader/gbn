###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Man In The Middle (MITM) Vulnerability - May17 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810993");
  script_version("2021-09-30T08:43:52+0000");
  script_cve_id("CVE-2017-7485");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-15 16:07:12 +0530 (Mon, 15 May 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Man In The Middle (MITM) Vulnerability - May17 (Windows)");

  script_tag(name:"summary", value:"PostgreSQL is prone to a man-in-the-middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'libpq' component of PostgreSQL, where the 'PGREQUIRESSL' environment
  variable was no longer enforcing a SSL/TLS connection to a PostgreSQL server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  man-in-the-middle attacker to strip the SSL/TLS protection from a connection
  between a client and a server.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.17,
  9.4.x before 9.4.12, 9.5.x before 9.5.7, and 9.6.x before 9.6.3.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 9.3.17 or
  9.4.12 or 9.5.7 or 9.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1746");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
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

if(vers =~ "^9\.3") {
  if(version_is_less(version:vers, test_version:"9.3.17")) {
    fix = "9.3.17";
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.12")) {
    fix = "9.4.12";
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.7")) {
    fix = "9.5.7";
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.3")) {
    fix = "9.6.3";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
