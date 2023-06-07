##############################################################################
# OpenVAS Vulnerability Test
#
# Description: IlohaMail Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2005 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14629");
  script_version("2021-06-17T10:24:47+0000");
  script_tag(name:"last_modification", value:"2021-06-17 10:24:47 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IlohaMail Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://ilohamail.org/");

  script_tag(name:"summary", value:"HTTP based detection of IlohaMail.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

# NB: Directories beyond http_cgi_dirs() come from a Google search -
#     'intitle:ilohamail "powered by ilohamail"' - and represent the more
#     popular installation paths currently. Still, http_cgi_dirs() should
#     catch the directory if its referenced elsewhere on the target.
testdirs = make_list();
foreach dir( make_list_unique( "/webmail", "/ilohamail", "/IlohaMail", "/mail", http_cgi_dirs( port:port ) ) ) {
  foreach subdir( make_list( "/source", "" ) ) {
    fulldir = str_replace( string: dir + subdir, find:"//", replace:"/" );
    testdirs = make_list( testdirs, fulldir );
  }
}

tesdirs = make_list_unique( testdirs );

foreach dir( testdirs ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" ) continue;

  if( egrep( string:res, pattern:'>Powered by <a href="http://ilohamail.org">IlohaMail<' ) ||
      egrep( string:res, pattern:"<h2>Welcome to IlohaMail" ) ||
      ( egrep( string:res, pattern:'<input type="hidden" name="logout" value=0>' ) &&
        egrep( string:res, pattern:'<input type="hidden" name="rootdir"' ) &&
        egrep( string:res, pattern:'<input type="password" name="password" value="" size=15' )
      ) ) {

    version = "unknown";
    cpe = "cpe:/a:ilohamail:ilohamail";
    set_kb_item( name:"ilohamail/detected", value:TRUE );

    # nb: Often the version string is embedded in index.php.
    # <br>&nbsp;<h2>Welcome to webmail! </h2>&nbsp;<b> Version 0.8.14-RC2</b><br><br><font color="#FFAAAA"><br>
    # <br>&nbsp;<h2>Welcome to webmail! </h2>&nbsp;<b> Version 0.8.10-Stable</b><br><br></td>
    ver = strstr( res, "<b> Version " );
    if( ! isnull( ver ) ) {
      ver = ver - "<b> Version ";
      if( strstr( res, "</b>" ) )
        ver = ver - strstr( ver, "</b>" );
      ver = ereg_replace( string:ver, pattern:"-stable", replace:"", icase:TRUE );
      version = ver;
      if( version =~ "-RC[0-9]+" ) {
        _cpe = ereg_replace( string:version, pattern:"-rc", replace:":rc", icase:TRUE );
        cpe += ":" + _cpe;
      } else {
       cpe += ":" + version;
      }
    }

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"IlohaMail",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                                              port:port );
  }
}

exit( 0 );
