###############################################################################
# OpenVAS Vulnerability Test
#
# Chora Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13849");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Chora Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects whether the remote host is running Chora and
  extracts version numbers and locations of any instances found.

  Chora is a PHP-based interface to CVS repositories from the Horde
  Project.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.horde.org/chora/");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

# Search for Chora in a couple of different locations.
# NB: Directories beyond http_cgi_dirs() come from a Google search -
#     'inurl:cvs.php horde' - and represent the more popular
#     installation paths currently. Still, http_cgi_dirs() should catch
#     the directory if its referenced elsewhere on the target.

installs = 0;

# Search for version number in a couple of different pages.
files = make_list( "/horde/services/help/?module=chora&show=about", "/cvs.php", "/README" );

foreach dir( make_list_unique( "/horde/chora", "/chora", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {

    res = http_get_cache( item:dir + file, port:port );
    if(!res)
      continue;

    if( egrep( string:res, pattern:"^HTTP/1\.[01] 200" ) ) {

      # Specify pattern used to identify version string.
      # - version 2.x
      if( file == "/horde/services/help/?module=chora&show=about" ) {
        pat = '>This is Chora +(.+).<';
      }
      # - version 1.x
      else if( file =~ "^/cvs.php" ) {
        pat = 'class=.+>CHORA +(.+)</a>';
      }
      # - other possibilities, but not necessarily good ones.
      #   nb: README is not guaranteed to be available and is sometimes
      #       inaccurate (eg, it reads 1.0 in version 1.2 and 1.2.1 in
      #       version 1.2.2).
      else if( file == "/README" ) {
        pat = '^Version +(.+) *$';
      }
      # - someone updated files but forgot to add a pattern???
      else {
        exit( 0 );
      }

      matches = egrep( pattern:pat, string:res );

      foreach match( split( matches ) ) {

        # Avoid false positives against other products shipping a README file (e.g. Tiki)
        if( file == "/README" && "Chora" >!< res )
          continue;

        match = chomp( match );
        ver = eregmatch( pattern:pat, string:match );
        if(isnull(ver))
          break;

        ver = ver[1];

        set_kb_item( name:"chora/detected", value:TRUE );

        installations[install] = ver;
        ++installs;

        cpe = build_cpe( value:ver, exp:"^([0-9.]+)", base:"cpe:/a:horde:chora:" );
        if( isnull( cpe ) )
          cpe = "cpe:/a:horde:chora";

        register_product( cpe:cpe, location:install, port:port, service:"www" );

        break; # nb: only worried about the first match.
      }
      if( installs ) break; # nb: if we found an installation, stop iterating through files.
    }
  }
}

if( installs ) {
  if( installs == 1 ) {
    foreach dir( keys( installations ) ) {
      # empty - just need to set 'dir'.
    }
    info = "Chora " + ver + " was detected on the remote host under the path " + dir + ".";
  } else {
    info = 'Multiple instances of Chora were detected on the remote host:\n\n';
    foreach dir( keys( installations ) ) {
      info += string("    ", installations[dir], ", installed under ", dir, "\n" );
    }
    info = chomp( info );
  }
  log_message( port:port, data:info );
}

exit( 0 );
