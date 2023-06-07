###############################################################################
# OpenVAS Vulnerability Test
#
# CVSTrac Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100091");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-03-30 14:26:52 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CVSTrac Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.cvstrac.org/");

  script_tag(name:"summary", value:"This host is running CVSTrac, a Web-Based Bug And Patch-Set Tracking
  System For CVS, Subversion and GIT.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/cgi-bin/run-cvstrac", "/cvstrac", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index";
  buf = http_get_cache( item:url, port:port );
  if( ! buf ) continue;

  if( egrep( pattern:'<a href="about">CVSTrac.*version [0-9.]+', string:buf ) ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:'<a href="about">CVSTrac.*version ([0-9.]+)' );
    if( ! isnull( version[1] ) ) vers = version[1];

    set_kb_item( name:"cvstrac/detected", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:cvstrac:cvstrac:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:cvstrac:cvstrac";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"CVSTrac",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
