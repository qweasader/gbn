# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812954");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-1053");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-02-28 10:48:11 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Information Disclosure Vulnerability (Feb 2018) - Windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the application creates
  temporary files in an insecure manner, where all temporary files made with
  'pg_upgrade' are world-readable");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attacker to gain access to sensitive information that may aid
  in further attacks.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.21,
  9.4.x before 9.4.16, 9.5.x before 9.5.11, 9.6.x before 9.6.7 and 10.x before
  10.2.");

  script_tag(name:"solution", value:"Update to version 10.2 or 9.6.7
  or 9.5.11 or 9.4.16 or 9.3.21 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1829");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102986");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-10-2.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-6-7.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-5-11.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-4-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-3-21.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
  if(version_is_less(version:vers, test_version:"9.3.21")) {
    fix = "9.3.21";
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.16")) {
    fix = "9.4.16";
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.11")) {
    fix = "9.5.11";
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.7")) {
    fix = "9.6.7";
  }
}

else if(vers =~ "^10\.") {
  if(version_is_less(version:vers, test_version:"10.2")) {
    fix = "10.2";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
