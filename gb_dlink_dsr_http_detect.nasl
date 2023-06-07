# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117074");
  script_version("2023-03-07T10:19:54+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-07 10:19:54 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"creation_date", value:"2020-12-11 12:52:04 +0000 (Fri, 11 Dec 2020)");
  script_name("D-Link DSR Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DSL Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );

url = "/";
buf = http_get_cache( port:port, item:url );
if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

# nb: Newer versions (> 1.x), the redirect is done in the body
# but with a HTTP 200 status code.
if( 'URL=/scgi-bin/platform.cgi"' >< buf ) {
  url = "/scgi-bin/platform.cgi";
  buf = http_get_cache( port:port, item:url );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    exit( 0 );
}

# <title>D-Link : Unified Services Router</title>
# <title>D-Link : Unified Services Router </title>
# nb: Note the trailing space after "Router" which has been seen like this on "live" devices.
# We're also using the case insensitive matching of "=~" to catch different possible variants.
# Both pattern exists for the "/" and "/scgi-bin/platform.cgi" URLs.
if( buf =~ "<title>D-Link\s*:\s*Unified Services Router\s*</title>" && "DSR-" >< buf ) {

  set_kb_item( name:"d-link/detected", value:TRUE );
  # nb: The new key for D-link active checks affecting multiple device types
  set_kb_item( name:"d-link/http/detected", value:TRUE );

  set_kb_item( name:"d-link/dsr/detected", value:TRUE );
  set_kb_item( name:"d-link/dsr/http/detected", value:TRUE );

  conclUrl   = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  fw_version = "unknown";
  os_app     = "D-Link DSR";
  os_cpe     = "cpe:/o:d-link:dsr";
  hw_version = "unknown";
  hw_app     = "D-Link DSR";
  hw_cpe     = "cpe:/h:d-link:dsr";
  model      = "unknown";
  install    = "/";

  # From DSR-250:
  # <div class="floatL txt01">Product Page: DSR-250</div>
  # DSR-1000N:
  # <div class="floatL txt01">Product Page: DSR-1000N</div>
  # Those can be translated as well:
  # <div class="floatL txt01">Produktseite: DSR-500N</div>
  #
  # From DSR-150 (both lines in one response):
  # <div class="logo FL">
  # Unified Services Router - DSR-150 </div>
  # DSR-250:
  # <div class="logo FL">
  # Unified Services Router - DSR-250 </div>
  # DSR-500AC:
  # <div class="logo FL">
  # Unified Services Router - DSR-500AC </div>
  # DSR-1000AC:
  # <div class="logo FL">
  # Unified Services Router - DSR-1000AC </div>
  # nb: Those above seems to be from newer DSR version > 1.x which doesn't expose their version anymore...
  #
  # As a fallback for translated pages the following should be used:
  # <td width="139" class="bg0 boxTitle">DSR-500N</td>
  mo = eregmatch( pattern:"(>Product Page\s*:\s*|>Produktseite\s*:\s*|Unified Services Router\s*-\s*|>)DSR-([^< ]+)", string:buf );
  if( mo[2] ) {
    model    = mo[2];
    os_concl = mo[0];
    hw_concl = mo[0];
    os_app += "-" + model + " Firmware";
    os_cpe += "-" + tolower( model ) + "_firmware";
    hw_app += "-" + model + " Device";
    hw_cpe += "-" + tolower( model );
    set_kb_item( name:"d-link/dsr/model", value:model );
  } else {
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "-unknown_model";
  }

  # From DSR-250:
  # <div class="floatR txt01">Firmware Version: 1.09B32_RU</div>
  # <div class="floatR txt01">Firmware Version: 1.09B32_WW</div>
  # DSR 500N:
  # <div class="floatR txt01">Firmware Version: 1.01B60</div>
  # DSR-1000N:
  # <div class="floatR txt01">Firmware Version: 1.09B61_WW</div>
  # Those can be translated as well:
  # <div class="floatR txt01">Firmware-Version: 1.08B77_WW</div>
  fw_ver = eregmatch( pattern:">Firmware[ -]Version\s*:\s*([^<]+)<", string:buf );
  if( fw_ver[1] )
    fw_version = fw_ver[1];

  # From DSR-250:
  # <div class="floatR txt01">Hardware Version: A2</div>
  # <div class="floatR txt01">Hardware Version: A1</div>
  # DSR-1000N:
  # <div class="floatR txt01">Hardware Version: A1</div>
  # Those can be translated as well:
  # <div class="floatR txt01">Hardware-Version: A1</div>
  hw_ver = eregmatch( pattern:">Hardware[ -]Version\s*:\s*([^<]+)<", string:buf );
  if( hw_ver[1] )
    hw_version = hw_ver[1];

  # Fallback for the translated strings mentioned previously (to catch all non-german/english devices).
  if( fw_version == "unknown" || hw_version == "unknown" ) {

    # The idea is to grab all "floatR txt01" classes first (the tested devices had only two, one for the
    # firmware and one for the hardware) ...
    hw_fw_class = egrep( string:buf, pattern:'<div class="floatR txt01">[^<]+<', icase:FALSE );
    if( hw_fw_class ) {
      # ... and then extract firmware and hardware versions based on some additional regex calls

      # The list is used so that the "^" match below doesn't catch multiple lines.
      list = split( hw_fw_class, keep:FALSE );
      foreach item( list ) {

        if( fw_version == "unknown" ) {
          # For the firmware we're assuming at least a version like 1.23 to be the firmware version
          fw_ver = eregmatch( pattern:">[^:]+:\s*([0-9.]{3,}[^<]*)<", string:item, icase:FALSE );
          if( fw_ver[1] ) {
            fw_version = fw_ver[1];
            continue;
          }
        }

        if( hw_version == "unknown" ) {
          # For the hardware D-Link is using something like A, B, C, A1, A2, A3, A4
          hw_ver = eregmatch( pattern:">[^:]+:\s*([A-Z][0-9]*)<", string:item, icase:FALSE );
          if( hw_ver[1] ) {
            hw_version = hw_ver[1];
            continue;
          }
        }
      }
    }
  }

  if( fw_version != "unknown" ) {
    os_cpe += ":" + tolower( fw_version );
    set_kb_item( name:"d-link/dsr/fw_version", value:fw_version );
    if( os_concl )
      os_concl += '\n';
    os_concl += fw_ver[0];
  }

  if( hw_version != "unknown" ) {
    hw_cpe += ":" + tolower( hw_version );
    set_kb_item( name:"d-link/dsr/hw_version", value:hw_version );
    if( hw_concl )
      hw_concl += '\n';
    hw_concl += hw_ver[0];
  }

  os_register_and_report( os:os_app, cpe:os_cpe, banner_type:"D-Link DSR Device Login Page", port:port, desc:"D-Link DSR Devices Detection (HTTP)", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app,
                                   version:fw_version,
                                   concluded:os_concl,
                                   concludedUrl:conclUrl,
                                   install:install,
                                   cpe:os_cpe );

  report += '\n\n' + build_detection_report( app:hw_app,
                                             version:hw_version,
                                             concluded:hw_concl,
                                             install:install,
                                             cpe:hw_cpe );

  log_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
