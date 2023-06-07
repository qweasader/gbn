# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902606");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2202");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("PHP SAPI_POST_HANDLER_FUNC() Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44874");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48259");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025659");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67999");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=312103");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to delete files from
  the root directory, which may aid in further attacks.");

  script_tag(name:"affected", value:"PHP version prior to 5.3.7");

  script_tag(name:"insight", value:"The flaw is due to an error in 'SAPI_POST_HANDLER_FUNC()' function in
  rfc1867.c when handling files via a 'multipart/form-data' POST request. which
  allows attacker to bypass security restriction.");

  script_tag(name:"solution", value:"Update to PHP version 5.3.7 or later.");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

##To check PHP version prior to 5.3.7
if(version_is_less(version:vers, test_version:"5.3.7")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.7");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
