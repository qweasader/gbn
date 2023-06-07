# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802590");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-0830");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-02-10 11:24:19 +0530 (Fri, 10 Feb 2012)");
  script_name("PHP 'php_register_variable_ex()' Remote Code Execution Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51830");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72911");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.3.10");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=15408");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/cve/CVE-2012-0830");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary PHP
  code on the system.");

  script_tag(name:"affected", value:"PHP Version 5.3.9 on windows.");

  script_tag(name:"insight", value:"The flaw is due to a logic error within the 'php_register_variable_ex()'
  function in php_variables.c when hashing form posts and updating a hash table,
  which can be exploited to execute arbitrary code.");

  script_tag(name:"solution", value:"Update to PHP Version 5.3.10 or later.");

  script_tag(name:"summary", value:"PHP is prone to a remote arbitrary code execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:vers, test_version:"5.3.9")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.10");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
