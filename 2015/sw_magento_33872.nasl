# Copyright (C) 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = 'cpe:/a:magentocommerce:magento';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105224");
  script_version("2022-04-14T06:42:08+0000");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-02-23 12:00:00 +0100 (Mon, 23 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0541");
  script_name("Magento Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"This web application is running with Magento which is prone to
  multiple cross-site scripting because the application fails to properly sanitize user-supplied input.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would execute in the context of
  the affected site, potentially allowing the attacker to steal cookie-based authentication credentials.");
  script_tag(name:"affected", value:"Magento 1.2.0 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Check for updated versions of Magento.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33872");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"1.2.0", test_version2:"1.2.1.1" ) ) {
  report = report_fixed_ver( installed_version:vers, vulnerable_range:"1.2.0 - 1.2.1.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
