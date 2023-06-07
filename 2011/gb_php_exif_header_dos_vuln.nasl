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
  script_oid("1.3.6.1.4.1.25623.1.0.802349");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2011-4566");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2011-12-01 11:41:26 +0530 (Thu, 01 Dec 2011)");
  script_name("PHP EXIF Header Denial of Service Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=60150");
  script_xref(name:"URL", value:"http://olex.openlogic.com/wazi/2011/php-5-4-0-medium/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-4566");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code,
  obtain sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"PHP version 5.4.0 beta 2 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in 'exif_process_IFD_TAG'
  function in the 'ext/exif/exif.c' file, Allows remote attackers to cause
  denial of service via crafted offset_val value in an EXIF header.");

  script_tag(name:"solution", value:"Update to PHP version 5.4.0 beta 4 or later.");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

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

##To check PHP version prior to 5.4.0
if(version_is_less(version:vers, test_version:"5.4.0")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.0 beta 4");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
