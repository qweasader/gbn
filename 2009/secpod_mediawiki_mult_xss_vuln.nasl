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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900469");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0737");
  script_name("MediaWiki Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33881");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33681");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0368");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker include arbitrary HTML or web
  scripts in the scope of the browser. This may lead to cross site scripting
  attacks and the attacker may gain sensitive information of the remote user
  or of the web application.");

  script_tag(name:"affected", value:"MediaWiki version prior to 1.13.4

  MediaWiki version prior to 1.12.4

  MediaWiki version prior to 1.6.12");

  script_tag(name:"insight", value:"Multiple flaws are caused as the data supplied by the user via unspecified
  vectors is not adequately sanitised before being passed into the file
  'config/index.php' of MediaWiki.");

  script_tag(name:"solution", value:"Apply the security updates accordingly.

  MediaWiki Version 1.13.4

  MediaWiki Version 1.12.4

  MediaWiki Version 1.6.12");

  script_tag(name:"summary", value:"MediaWiki is prone to Multiple XSS Vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"1.13", test_version2:"1.13.3" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.3" ) ||
    version_in_range( version:vers, test_version:"1.6", test_version2:"1.6.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.13.4, 1.12.4 or 1.6.12" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );