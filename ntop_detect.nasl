###############################################################################
# OpenVAS Vulnerability Test
#
# Ntop Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100256");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-10-17T11:13:19+0000");
  script_tag(name:"last_modification", value:"2022-10-17 11:13:19 +0000 (Mon, 17 Oct 2022)");
  script_tag(name:"creation_date", value:"2009-08-23 12:14:46 +0200 (Sun, 23 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Ntop Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ntop/banner");

  script_tag(name:"summary", value:"Detection of Ntop

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:3000 );
buf = http_get_remote_headers( port:port );

if( concl = egrep( pattern:"Server: ntop", string:buf, icase:TRUE ) ) {

  concl = chomp( concl );
  version = "unknown";
  install = "/";

  ver = eregmatch( string:buf, pattern: "Server: ntop/([0-9.]+)", icase:TRUE );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    concl = ver[0];
  }

  set_kb_item( name:"ntop/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ntop:ntop:" );
  if( ! cpe )
    cpe = "cpe:/a:ntop:ntop";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Ntop",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concl ),
               port:port );
}

exit( 0 );
