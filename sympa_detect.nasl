###################################################################
# OpenVAS Vulnerability Test
#
# Sympa Detection
#
# LSS-NVT-2009-013
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102013");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Sympa Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  script_xref(name:"URL", value:"http://www.sympa.org/");

  script_tag(name:"summary", value:"The remote host is running Sympa, an open source (GNU GPL) mailing list
  management (MLM) software suite written in Perl.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/wws", "/wwsympa", "/sympa", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/", port:port );

  #TD NOWRAP><I>Powered by</I></TD>
  #<TD><A HREF="http://www.sympa.org/">
  #       <IMG SRC="/icons/sympa/logo-s.png" ALT="Sympa 3.4.3" BORDER="0" >
  #
  # or:
  #
  #<a href="http://www.sympa.org"> Powered by Sympa 6.2.16</a>
  #</footer>
  pat = '(Powered by ([^>]*>)?Sympa ?v?|www\\.sympa\\.org.*ALT=.Sympa )([0-9.]+)';
  match = egrep( pattern:pat, string:buf, icase:TRUE );

  if( match || egrep( pattern:"<meta name=.generator. content=.Sympa", string:buf, icase:TRUE ) ) {
    version = "unknown";

    set_kb_item( name:"sympa/detected", value:TRUE );

    item = eregmatch( pattern:pat, string:match, icase:TRUE );
    if( ! isnull( item[3] ) )
      version = item[3];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sympa:sympa:" );
    if( ! cpe )
      cpe = "cpe:/a:sympa:sympa";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Sympa", version:version, install:install, cpe:cpe,
                                              concluded:item[0] ),
                 port:port );
  }
}

exit( 0 );
