# Copyright (C) 2008 Greenbone Networks GmbH
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

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900023");
  script_version("2021-09-01T13:34:42+0000");
  script_tag(name:"last_modification", value:"2021-09-01 13:34:42 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2008-08-07 17:25:49 +0200 (Thu, 07 Aug 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2008-3569");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XAMPP Multiple XSS Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("xampp/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Xampp is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Xampp Linux version 1.7.3 or later.");

  script_tag(name:"insight", value:"The flaw is due the input passed to the parameter text in iart.php and
  ming.php files are not santised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code.");

  script_tag(name:"affected", value:"Xampp Linux 1.6.7 and prior on Linux.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/495096");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(port:port, cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.6.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.7.3", install_path: location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
