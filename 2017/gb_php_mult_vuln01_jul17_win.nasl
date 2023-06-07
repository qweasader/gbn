# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.811481");
  script_version("2022-07-22T10:11:18+0000");
  script_cve_id("CVE-2017-7890", "CVE-2017-9224", "CVE-2017-9225", "CVE-2017-9226", "CVE-2017-9227",
                "CVE-2017-9228", "CVE-2017-9229", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11628",
                "CVE-2017-12933");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-22 10:11:18 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:38:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-07-11 19:28:21 +0530 (Tue, 11 Jul 2017)");
  script_name("PHP Multiple Vulnerabilities (Jul 2017 - 01) - Windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An ext/date/lib/parse_date.c out-of-bounds read affecting the php_parse_date function.

  - The openssl extension PEM sealing code did not check the return value of the OpenSSL sealing
  function.

  - lack of bounds checks in the date extension's timelib_meridian parsing code.

  - A stack-based buffer overflow in the zend_ini_do_op() function in the 'Zend/zend_ini_parser.c'
  script.

  - The GIF decoding function gdImageCreateFromGifCtx in gd_gif_in.c in the GD Graphics Library
  (aka libgd) does not zero colorMap arrays before use.

  - Heap buffer overread (READ: 1) finish_nested_data from unserialize

  - Add oniguruma upstream fix");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to leak
  information from the interpreter, crash PHP interpreter and also disclose sensitive information.");

  script_tag(name:"affected", value:"PHP versions before 5.6.31, 7.x before 7.0.21 and 7.1.x before
  7.1.7.");

  script_tag(name:"solution", value:"Update to version 5.6.31, 7.0.21, 7.1.7 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99492");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99550");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99612");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99489");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

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

if(version_is_less(version:vers, test_version:"5.6.31"))
  fix = "5.6.31";

else if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.20"))
  fix = "7.0.21";

else if(vers =~ "^7\.1" && version_is_less(version:vers, test_version:"7.1.7"))
  fix = "7.1.7";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);