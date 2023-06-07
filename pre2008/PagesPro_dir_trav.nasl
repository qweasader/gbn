###############################################################################
# OpenVAS Vulnerability Test
#
# Pages Pro CD directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# Reference
# http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html
#
# Credits:
# Philippe de Brito (Le Mamousse) discovered the flaw and sent his exploit.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11221");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Pages Pro CD directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8100);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.cert.ssi.gouv.fr/site/CERTA-2002-ALE-007/");

  script_tag(name:"solution", value:"Upgrade it (version 2003) or uninstall this product");
  script_tag(name:"summary", value:"A security vulnerability in the 'Pages Pro' allows anybody
  to read or modify files that would otherwise be inaccessible using a
  directory traversal attack.");
  script_tag(name:"impact", value:"A cracker may use this to read or write sensitive files or even
  make a phone call.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8100 );

files = traversal_files();

foreach file( keys( files ) ) {

  url = "/note.txt?F_notini=&T_note=&nomentreprise=blah&filenote=../../" + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
