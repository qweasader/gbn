###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Unified IP Phone Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105533");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-02-09 09:44:27 +0100 (Tue, 09 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cisco Unified IP Phone Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

buf = http_get_cache( port:port, item:"/" );

if( "<TITLE>Cisco Systems, Inc.</TITLE>" >!< buf || buf !~ 'Cisco (Unified )?IP Phone' ) {
  req = http_get(port: port, item: "/CGI/Java/Serviceability?adapter=device.statistics.device");
  buf = http_keepalive_send_recv(port: port, data: req);
  if( "<TITLE>Cisco Systems, Inc.</TITLE>" >!< buf || buf !~ 'Cisco (Unified )?IP Phone' )
     exit( 0 );
}

model = 'unknown';
vers = 'unknown';
app = 'Cisco Unified IP Phone';

mod = eregmatch( pattern:'Cisco (Unified )?IP Phone ([^ ),]+)', string:buf );
if( ! isnull( mod[2] ) )
{
  model = mod[2];
  set_kb_item( name:"cisco/ip_phone/model", value:model );
  app += ' (' + model + ')';
}

hn = eregmatch( pattern:'Cisco (Unified )?IP Phone ([^ ),]+ \\(([^)]+)\\))', string:buf );
if( ! isnull( hn[3] ) )
{
  hostname = hn[3];
  set_kb_item( name:"cisco/ip_phone/hostname", value:hostname );
}

lines = split( buf, sep:"<TR>", keep:FALSE );

foreach line( lines )
{
  if( ! version[1] )
    version = eregmatch( pattern:'<TD><B>\\s*Version</B></TD><td width=20></TD><TD><B>([^<]+)</B></TD></TR>', string:line );

  if( ! version[1] )
    # Version</B></TD><TD><B>sip78xx.12-5-1SR3-74</B>
    version = eregmatch( pattern:"Version</B></TD><TD><B>(sip[^>]+)<", string:line );

  if( ! phone_dn[1] )
    phone_dn = eregmatch( pattern:'<TD><B>\\s*Phone DN</B></TD><td width=20></TD><TD><B>([^<]+)</B></TD></TR>', string:line );

  # Phone DN</B></TD><TD><B>7654951539</B>
  if( ! phone_dn[1] )
    phone_dn = eregmatch( pattern:'Phone DN</B></TD><TD><B>([^<]+)<', string:line );

  if( version[1] && phone_dn[1] ) break;
}

cpe = "cpe:/h:cisco:unified_ip_phone";

if( version[1] )
{
  # replace unicode
  version = ereg_replace(pattern: "&#x2D;", string: version[1], replace: "-");
  cpe += ':' + version;
  vers = version;
  set_kb_item( name:"cisco/ip_phone/version", value:vers );
}

if( phone_dn[1] )
{
  pdn = phone_dn[1];
  set_kb_item( name:"cisco/ip_phone/phone_dn", value:phone_dn );
}

os_register_and_report( os:"Cisco Native Unix (CNU) on Cisco Unified IP Phone", cpe:"cpe:/o:cisco:cnu-os", banner_type:"HTTP banner", port:port, desc:"Cisco Unified IP Phone Detection", runs_key:"unixoide" );

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = 'Detected ' + app + '\n' +
         'Version:   ' + vers + '\n';

if( hostname ) report += 'Hostname: ' + hostname + '\n';
if( pdn ) report += 'Phone DN:  ' + pdn + '\n';

log_message( port:port, data:report );

exit(0);
