# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902070");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)");
  script_cve_id("CVE-2010-1647", "CVE-2010-1648");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("MediaWiki Cross-site Scripting (XSS) and Cross-site Request Forgery (CSRF) Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=23687");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=23371");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-May/000091.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary web
  script or HTML and to hijack the authentication of users.");

  script_tag(name:"affected", value:"MediaWiki version 1.15 before 1.15.4 and 1.16 before 1.16 beta 3.");

  script_tag(name:"insight", value:"- A flaw is present while processing crafted Cascading Style Sheets (CSS)
  strings, which are processed as scripts

  - An error is present in the 'Special:Userlogin' form, which allows remote
  attackers to hijack the authentication of users for requests that create
  accounts or reset passwords.");

  script_tag(name:"solution", value:"Upgrade to MediaWiki version 1.15.4 or 1.16 beta 3 or later.");

  script_tag(name:"summary", value:"MediaWiki is prone to Cross-site Scripting and Cross-Site Request Forgery vulnerabilities.");

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

if( version_in_range( version:vers, test_version:"1.15.0", test_version2:"1.15.3" ) ||
    version_in_range( version:vers, test_version:"1.16.0", test_version2:"1.16.0.beta2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.15.4 or 1.16.0.beta3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );