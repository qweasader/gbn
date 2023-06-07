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
  script_oid("1.3.6.1.4.1.25623.1.0.100675");
  script_version("2021-11-30T08:05:58+0000");
  script_tag(name:"last_modification", value:"2021-11-30 08:05:58 +0000 (Tue, 30 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nominum Vantio Detection (DNS)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("dns_server_tcp.nasl", "dns_server.nasl");
  script_mandatory_keys("dns/server/detected");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");

  script_xref(name:"URL", value:"http://www.nominum.com/");

  script_tag(name:"summary", value:"DNS based detection of Nominum Vantio.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

function getVersion( data, port, proto ) {

  local_var data, port, proto;
  local_var version, ver, cpe;

  if( ! data || "nominum vantio" >!< tolower( data ) )
    return;

  version = "unknown";
  ver = eregmatch( pattern:"Nominum Vantio ([0-9.]+)", string:data, icase:TRUE );
  if( ver[1] )
    version = ver[1];

  set_kb_item( name:"nominum/vantio/detected", value:TRUE );

  # CPE not registered yet
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nominum:vantio:" );
  if( ! cpe )
    cpe = "cpe:/a:nominum:vantio";

  register_product( cpe:cpe, location:port + "/" + proto, port:port, proto:proto );
  log_message( data:build_detection_report( app: "Nominum Vantio",
                                            version:version,
                                            install:port + "/" + proto,
                                            cpe:cpe,
                                            concluded:data ),
                                            port:port,
                                            proto:proto );
}

udp_ports = get_kb_list( "DNS/udp/version_request" );
foreach port( udp_ports ) {

  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"udp" );
}

tcp_ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_ports ) {

  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );