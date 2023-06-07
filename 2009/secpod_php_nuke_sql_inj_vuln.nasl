# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpnuke:php-nuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900339");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6728");
  script_name("PHP-Nuke Sections Module SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-nuke/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause SQL Injection attack, gain
  sensitive information about the database used by the web application or can cause
  arbitrary code execution inside the context of the web application.");

  script_tag(name:"affected", value:"PHP-Nuke version prior to 8.0.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user supplied input through the
  'artid' parameter in a printable action to modules.php");

  script_tag(name:"solution", value:"Upgrade to PHP-Nuke version 8.0 or later.");

  script_tag(name:"summary", value:"PHP-Nuke is prone to an SQL injection (SQLi) vulnerability.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/488653");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27958");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/data/vulnerabilities/exploits/27958.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"8.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.0" );
  security_message(port:port, data:report );
  exit( 0 );
}

exit( 99 );