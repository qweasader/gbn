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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812512");
  script_version("2023-01-19T10:10:48+0000");
  script_cve_id("CVE-2016-10712");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 16:29:00 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-20 12:02:20 +0530 (Tue, 20 Feb 2018)");
  script_name("PHP 'stream_get_meta_data' Privilege Escalation Vulnerability (Linux)");

  script_tag(name:"summary", value:"PHP is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the function
  stream_get_meta_data of the component File Upload. The manipulation as part
  of a Return Value leads to a privilege escalation vulnerability (Metadata).");

  script_tag(name:"impact", value:"Successfully exploitation will allow an attacker
  to update the 'metadata' and affect on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"PHP versions before 5.5.32, 7.0.x before
  7.0.3, and 5.6.x before 5.6.18 on Linux.");

  script_tag(name:"solution", value:"Update to PHP version 5.5.32, 7.0.3,
  or 5.6.18 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71323");
  script_xref(name:"URL", value:"https://git.php.net/?p=php-src.git;a=commit;h=6297a117d77fa3a0df2e21ca926a92c231819cd5");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.5.32")){
  fix = "5.5.32";
}

else if(version_in_range(version:vers, test_version:"7.0.0", test_version2:"7.0.2")){
  fix = "7.0.3";
}

else if(vers =~ "^5\.6" && version_is_less(version:vers, test_version:"5.6.18")){
  fix = "5.6.18";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
