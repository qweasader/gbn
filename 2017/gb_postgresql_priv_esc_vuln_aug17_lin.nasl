###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Privilege Escalation Vulnerability - August17 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811582");
  script_version("2023-05-19T09:09:15+0000");
  script_cve_id("CVE-2017-7548");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-05-19 09:09:15 +0000 (Fri, 19 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-16 11:09:00 +0000 (Tue, 16 May 2023)");
  script_tag(name:"creation_date", value:"2017-08-17 12:50:23 +0530 (Thu, 17 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Privilege Escalation Vulnerability - August17 (Linux)");

  script_tag(name:"summary", value:"PostgreSQL is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the 'lo_put' function
  which should require the same permissions as 'lowrite' function, but there
  was a missing permission check.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to gain extra privileges and conduct a denial of service
  condition.");

  script_tag(name:"affected", value:"PostgreSQL version 9.4.x before 9.4.13,
  and 9.5.x before 9.5.8 and 9.6.x before 9.6.4.");

  script_tag(name:"solution", value:"Upgrade to version 9.4.13 or 9.5.8 or
  9.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1772/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100276");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9.5.8.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9.4.13.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.13")) {
    fix = "9.4.13";
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.8")) {
    fix = "9.5.8";
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.4")) {
    fix = "9.6.4";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
