# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903025");
  script_version("2022-02-15T13:40:32+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-04-30 12:42:29 +0530 (Mon, 30 Apr 2012)");
  script_name("HelpDesk Multiple Persistent Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18145");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"HelpDesk");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied input
  passed via the 'searchvalue' parameter to 'knowledgebase.php' and 'client_name' parameter to
  'register.php', which allows attackers to execute arbitrary HTML and script code in the context
  of an affected application or site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"HelpDesk is prone to multiple persistent cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

## List possible dirs
foreach dir( make_list_unique( "/", "/helpdesk", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( ">HelpDesk" >< buf && "Powered by <" >< buf ) {

    url = dir + '/knowledgebase.php?act=search&searchvalue="><script>alert' +
                '(document.cookie)</script>';

    if( http_vuln_check( port:port, url:url, check_header:TRUE, extra_check:"HelpDesk",
                         pattern:"><script>alert\(document.cookie\)</script>" ) ) {
      report = http_report_vuln_url( url:url, port:port );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
