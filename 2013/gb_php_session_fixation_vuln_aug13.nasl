# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803737");
  script_version("2022-09-15T10:11:06+0000");
  script_cve_id("CVE-2011-4718");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2013-08-19 12:03:50 +0530 (Mon, 19 Aug 2013)");
  script_name("PHP Sessions Subsystem Session Fixation Vulnerability (Aug 2013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "gb_php_ssh_login_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Session fixation vulnerability in the Sessions subsystem in PHP
  allows remote attackers to hijack web sessions by specifying a session ID.");

  script_tag(name:"affected", value:"PHP versions prior to 5.5.2 if an application is using the
  Sessions subsystem of PHP.");

  script_tag(name:"solution", value:"- Update to PHP version 5.5.2 or later and set
  'session.use_strict_mode' in php.ini to 'On'

  - make adoptive session with user land code as described in the referenced PHP strict_sessions
  document");

  script_xref(name:"URL", value:"https://wiki.php.net/rfc/strict_sessions");
  script_xref(name:"URL", value:"https://wiki.php.net/rfc/strict_sessions#current_solution");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=169b78eb79b0e080b67f9798708eb3771c6d0b2f");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=25e8fcc88fa20dc9d4c47184471003f436927cde");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2011-4718");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54562");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2011-4718");

  # Mitigation is possible on code site. An application might also not use the PHP sessions at all.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"5.5.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.5.2", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
