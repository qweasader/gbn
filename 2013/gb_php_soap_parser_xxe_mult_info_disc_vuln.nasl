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
  script_oid("1.3.6.1.4.1.25623.1.0.803764");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-1824");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-09-24 11:54:43 +0530 (Tue, 24 Sep 2013)");
  script_name("PHP SOAP Parser Multiple Information Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"PHP is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP 5.3.22 or 5.4.12 or later.");

  script_tag(name:"insight", value:"Flaws are due to the way SOAP parser process certain SOAP objects (due to
  allowed expansion of XML external entities during SOAP WSDL files parsing).");

  script_tag(name:"affected", value:"PHP version before 5.3.22 and 5.4.x before 5.4.12");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62373");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=afe98b7829d50806559acac9b530acb8283c3bf4");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.3.22") ||
   version_in_range(version:vers, test_version:"5.4.0", test_version2:"5.4.11")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.22/5.4.12");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
