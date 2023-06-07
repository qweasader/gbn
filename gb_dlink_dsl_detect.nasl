# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.812377");
  script_version("2023-03-07T10:19:54+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-07 10:19:54 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-01-03 16:00:40 +0530 (Wed, 03 Jan 2018)");
  script_name("D-Link DSL Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("D-LinkDSL/banner");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DSL Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

foreach url( make_list( "/", "/cgi-bin/webproc" ) ) {

  buf = http_get_cache( port:port, item:url );

  # Server: Linux, WEBACCESS/1.0, DSL-2890AL Ver AU_1.02.10
  # Server: uhttpd
  if( ! egrep( string:buf, pattern:"^Server\s*:\s*(Boa|micro_httpd|Linux|RomPager|uhttpd)", icase:TRUE ) && "/cgi-bin/SETUP/sp_home.asp" >!< buf && "/page/login/login.html" >!< buf )
    continue;

  # Seen on DSL-2888A
  if( buf =~ "Location: /page/login/login.html" )
    buf = http_get_cache( port:port, item:"/page/login/login.html" );

  # NOTE: Those are NO D-Link but Asus Routers:
  # WWW-Authenticate: Basic realm="DSL-N10"
  # WWW-Authenticate: Basic realm="DSL-N14U"
  # They have a separate "Server: httpd" banner which is skipped above.
  #
  # NOTE2: There are also a few with the following out:
  # WWW-Authenticate: Basic realm="DSL Router"
  # Server: micro_httpd
  # Those are very unlikely D-Link devices...

  # <div class="pp">Product Page : DSL-2890AL<a href="javascript:check_is_modified('http://support.dlink.com/')"><span id="model" align="left"></span></a></div>
  if( 'WWW-Authenticate: Basic realm="DSL-([0-9A-Z]+)' >< buf || "<title>D-Link DSL-" >< buf ||
      ( "D-Link" >< buf && ( "Product Page : DSL-" >< buf || "Server: Linux, WEBACCESS/1.0, DSL-" >< buf ) ) ||
      ( "DSL Router" >< buf && buf =~ "Copyright.*D-Link Systems" ) ||
      ( "<TITLE>DSL-" >< buf && "var PingDlink" >< buf ) ||
      ( 'var Manufacturer="D-Link"' >< buf && 'var ModelName="DSL-' >< buf ) ) {

    # nb: some of these keys need to be moved to the consolidation later
    set_kb_item( name:"d-link/detected", value:TRUE );
    # nb: The new key for D-link active checks affecting multiple device types
    set_kb_item( name:"d-link/http/detected", value:TRUE );

    set_kb_item( name:"d-link/dsl/detected", value:TRUE );
    set_kb_item( name:"d-link/dsl/http/detected", value:TRUE );

    conclUrl   = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    fw_version = "unknown";
    os_app     = "D-Link DSL";
    os_cpe     = "cpe:/o:d-link:dsl";
    hw_version = "unknown";
    hw_app     = "D-Link DSL";
    hw_cpe     = "cpe:/h:d-link:dsl";
    model      = "unknown";
    install    = "/";

    # For DSL-2888A which differs from others (again)
    # var ModelName="DSL-2888A";
    mo = eregmatch( pattern:'(Product Page ?: ?|var ModelName="|Server: Linux, WEBACCESS/1\\.0, )?DSL-([0-9A-Z]+)', string:buf );
    if( mo[2] ) {
      model    = mo[2];
      os_concl = mo[0];
      hw_concl = mo[0];
      os_app += "-" + model + " Firmware";
      os_cpe += "-" + tolower( model ) + "_firmware";
      hw_app += "-" + model + " Device";
      hw_cpe += "-" + tolower( model );
      set_kb_item( name:"d-link/dsl/model", value:model );
    } else {
      os_app += " Unknown Model Firmware";
      os_cpe += "-unknown_model_firmware";
      hw_app += " Unknown Model Device";
      hw_cpe += "-unknown_model";
    }

    # <div class="fwv">Firmware Version : AU_1.02.06<span id="fw_ver" align="left"></span></div>
    # var SoftwareVersio="AU_2.00";
    # var SoftwareVersio="AU_2.12";
    # var SoftwareVersio="AU_2.31";
    # var SoftwareVersio="EG_1.00b4";
    # var SoftwareVersio="ME_1.01";
    # nb: the missing "n" in "SoftwareVersio" was seen like this. It is unclear if this is a
    # bug in some specific firmware version (HardwareVersion is using the "n") so we're checking
    # both in this regex:
    fw_ver = eregmatch( pattern:'(Firmware Version ?: |var SoftwareVersion?=")(AU_|V|EG_|ME_)?([0-9.]+)', string:buf );
    if( fw_ver[3] ) {
      fw_version = fw_ver[3];
      os_cpe    += ":" + fw_version;
      set_kb_item( name:"d-link/dsl/fw_version", value:fw_version );
      if( os_concl )
        os_concl += '\n';
      os_concl += fw_ver[0];
    }

    if( fw_version == "unknown" ) {
      # nb: Not available on all DSL- devices
      url2   = "/ayefeaturesconvert.js";
      req    = http_get( port:port, item:url2 );
      res    = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      fw_ver = eregmatch( string:res, pattern:'var AYECOM_FWVER="([0-9]\\.[0-9]+)";' );
      if( fw_ver[1] ) {
        fw_version = fw_ver[1];
        os_cpe    += ":" + fw_version;
        set_kb_item( name:"d-link/dsl/fw_version", value:fw_version );
        if( conclUrl )
          conclUrl += '\n';
        conclUrl += http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        if( os_concl )
          os_concl += '\n';
        os_concl += fw_ver[0];
      }
    }

    if( fw_version == "unknown" ) {
      # e.g. on DSL-2875AL
      # var showfwver='1.00.01';
      url2 = "/cgi-bin/login.asp";
      res = http_get_cache( port:port, item:url2 );
      fw_ver = eregmatch( pattern:"var showfwver='([0-9.]+)'", string:res );
      if( ! isnull( fw_ver[1] ) ) {
        fw_version = fw_ver[1];
        set_kb_item( name:"d-link/dsl/fw_version", value:fw_version );
        if( conclUrl )
          conclUrl += '\n';
        conclUrl += http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        if( os_concl )
          os_concl += '\n';
        os_concl += fw_ver[0];
      }
    }

    # <div class="hwv">Hardware Version : A1<span id="hw_ver" align="left"></span></div>
    # var HardwareVersion="T1";
    # nb: See note on "SoftwareVersio" above.
    hw_ver = eregmatch( pattern:'(>Hardware Version ?: |var HardwareVersion?=")([0-9A-Za-z.]+)', string:buf );
    if( hw_ver[2] ) {
      hw_version = hw_ver[2];
      hw_cpe    += ":" + tolower( hw_version );
      set_kb_item( name:"d-link/dsl/hw_version", value:hw_version );
      if( hw_concl )
        hw_concl += '\n';
      hw_concl += hw_ver[0];
    }

    os_register_and_report( os:os_app, cpe:os_cpe, banner_type:"D-Link DSL Device Login Page/Banner", port:port, desc:"D-Link DSL Devices Detection", runs_key:"unixoide" );
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
}

exit( 0 );
