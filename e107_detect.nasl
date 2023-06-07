###############################################################################
# OpenVAS Vulnerability Test
#
# e107 Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100133");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_name("e107 Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://e107.org/");

  script_tag(name:"summary", value:"This host is running e107, a content management system written in PHP and
  using the popular open source MySQL database system for content storage.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit(0);

foreach dir ( make_list_unique( "/", "/e107", "/cms", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/e107_admin/admin.php", port:port );
  req2 = http_get( item:dir + "/login.php", port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  buf2 = http_keepalive_send_recv( port:port, data:req2 );
  buf3 = http_get_cache( item:dir + "/news.php", port:port );

  if( egrep( pattern:'This site is powered by <a.*e107.org.*[^>]+>e107</a>', string:buf, icase:TRUE ) ||
      egrep( pattern:'src=\'/e107', string:buf2, icase:TRUE ) ||
      "e107 Powered Website: News" >< buf3 ) {
    set_kb_item( name:"e107/installed", value:TRUE );

    version = "unknown";
    concluded = "unknown";

    req = http_get( item:dir + "/e107_core/xml/default_install.xml", port:port );
    res = http_keepalive_send_recv( data:req, port:port );
    vers = eregmatch( pattern:'<core name="version">([0-9.]+)</core>', string:res, icase:TRUE );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      concluded = vers[0];
      concluded_url = http_report_vuln_url( port:port, url:dir + "/e107_core/xml/default_install.xml", url_only:TRUE );
    }

    cpe = 'cpe:/a:e107:e107:';

    register_and_report_cpe( app:"e107",
                             ver:version,
                             concluded:concluded,
                             base:cpe,
                             expr:'([0-9.]+)',
                             insloc:install,
                             regService:"www",
                             conclUrl:concluded_url,
                             regPort:port );

    exit( 0 );
  }
}

exit( 0 );
