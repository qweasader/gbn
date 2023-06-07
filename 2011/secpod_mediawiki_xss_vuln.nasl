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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902380");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-1765");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("MediaWiki Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=702512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47722");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=28534");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-May/000098.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"MediaWiki version before 1.16.5.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling the file extension such as
  '.shtml' at the end of the query string, along with URI containing a
  '%2E' sequence in place of the .(dot) character.");

  script_tag(name:"solution", value:"Upgrade to MediaWiki 1.16.5 or later.");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit(0);
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/api%2Ephp?action=query&meta=siteinfo&format=json&siprop=%3Cbody%20onload=alert('document.cookie')%3E.shtml";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( res !~ "^HTTP/1\.[01] 200" ) exit( 99 );

if( "Invalid file extension found in PATH_INFO or QUERY_STRING." >!< res &&
    "<body onload=alert('document.cookie')>.shtml" >< res &&
    "Status: 403 Forbidden" >!< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
