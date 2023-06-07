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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103018");
  script_version("2022-07-04T10:18:32+0000");
  script_tag(name:"last_modification", value:"2022-07-04 10:18:32 +0000 (Mon, 04 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-01-07 13:52:38 +0100 (Fri, 07 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("OpenEMR Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.open-emr.org/");

  script_tag(name:"summary", value:"HTTP based detection of OpenEMR.");

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

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/openemr", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/interface/login/login.php";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && "OpenEMR" >< buf ) {

    set_kb_item( name:"openemr/installed", value:TRUE );
    set_kb_item( name:"openemr/http/detected", value:TRUE );

    concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    version = "unknown";
    ver = eregmatch( pattern:'<div class="version">[\r\n ]*v([0-9dev (.-]+)', string:buf );
    if( ver[1] ) {
      version = ver[1];
      concluded = ver[0];
    }

    if( version == "unknown" ) {
      url = dir + "/admin.php";
      buf = http_get_cache( item:url, port:port );

      ## the following regex is matching to this (for example): "<td>5.0.0 (3)</td><td><a href="[...]">Log In</a></td>"
      ver = eregmatch( pattern:"<td>([0-9dev (.-]+)\)?</td>.*Log In</a></td>", string:buf );
      if( ver[1] ) {
        version = ver[1];
        concluded = ver[0];
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      url = dir +  "/interface/login/login_title.php";
      buf = http_get_cache( item:url, port:port );

      ver = eregmatch( string:buf, pattern:"OpenEMR[^=/]+.*v([0-9dev (.-]+)", icase:TRUE );
      if( ver[1] ) {
        version = ver[1];
        concluded = ver[0];
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      url = dir + "/contrib/util/ubuntu_package_scripts/production/changelog.Debian";
      buf = http_get_cache( item:url, port:port );

      # openemr (5.0.2-1) stable; urgency=low
      ver = eregmatch( string:buf, pattern:"openemr \(([^)]+)\)" );
      if( ver[1] ) {
        version = ver[1];
        concluded = ver[0];
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    # nb: Just some final rewriting of the extracted version
    if( version != "unknown" )
      version = ereg_replace( pattern:" \(", string:version, replace:"-" );

    # replaced until get_version_from_cpe() is being fixed
    # cpe = build_cpe( value:version, exp:"^([0-9dev.]+)-?([0-9])?", base:"cpe:/a:open-emr:openemr:" );
    cpe = build_cpe( value:version, exp:"^([0-9dev\.\-]+)", base:"cpe:/a:open-emr:openemr:" );
    if( ! cpe )
      cpe = "cpe:/a:open-emr:openemr";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"OpenEMR",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concluded,
                                              concludedUrl:concUrl ),
                 port:port );
  }
}

exit( 0 );
