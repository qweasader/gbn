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
  script_oid("1.3.6.1.4.1.25623.1.0.813754");
  script_version("2023-02-28T10:20:42+0000");
  script_cve_id("CVE-2018-10925");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:38:00 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-08-13 18:20:47 +0530 (Mon, 13 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Multiple Vulnerabilities (Aug 2018) - Linux");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to a missing
  authorization on certain statements involved with 'INSERT ... ON CONFLICT
  DO UPDATE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read arbitrary bytes of server memory and update other columns which should
  have been restricted otherwise.");

  script_tag(name:"affected", value:"PostgreSQL versions before 10.5, 9.6.10
  and 9.5.14.");

  script_tag(name:"solution", value:"Update to version 10.5 or 9.6.10
  or 9.5.14 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105052");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-10-5.html#id-1.11.6.5.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-6-10.html#id-1.11.6.11.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-5-14.html#id-1.11.6.22.5");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(vers =~ "^9\.5\.") {
  if(version_is_less(version:vers, test_version: "9.5.14")) {
    fix = "9.5.14";
  }
}

else if(vers =~ "^9\.6\.") {
  if(version_is_less(version:vers, test_version: "9.6.10")) {
    fix = "9.6.10";
  }
}

else if(vers =~ "^10\.") {
  if(version_is_less(version:vers, test_version: "10.5")) {
    fix = "10.5";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
