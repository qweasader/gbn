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

CPE = "cpe:/a:hp:onboard_administrator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103795");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-10-01 11:28:03 +0200 (Tue, 01 Oct 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"7.6");

  script_cve_id("CVE-2012-0128", "CVE-2012-0129", "CVE-2012-0130");

  script_name("HP Onboard Administrator < 3.50 Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52862");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03263573");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_hp_onboard_administrator_detect.nasl");
  script_mandatory_keys("hp/onboard_administrator/detected");

  script_tag(name:"impact", value:"An attacker may exploit these issues to obtain sensitive information,
  bypass certain security restrictions, and redirect a user to a
  potentially malicious site. This may aid in phishing attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HP Onboard Administrator is prone to:

  1. A URI-redirection vulnerability

  2. An information-disclosure vulnerability

  3. A security-bypass vulnerability");

  script_tag(name:"solution", value:"Update to version 3.50 or later.");

  script_tag(name:"summary", value:"HP Onboard Administrator is prone to multiple security vulnerabilities.");

  script_tag(name:"affected", value:"HP Onboard Administrator (OA) versions prior to 3.50.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"3.50")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.50");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
