###############################################################################
# OpenVAS Vulnerability Test
#
# Do not print on AppSocket and socketAPI printers
#
# Authors:
# Laurent Facq <facq@u-bordeaux.fr> 05/2004
# 99% based on dont_scan_printers by Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 by Laurent Facq
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12241");
  script_version("2023-05-26T16:08:11+0000");
  script_tag(name:"last_modification", value:"2023-05-26 16:08:11 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Do not print on AppSocket and socketAPI printers");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2005 by Laurent Facq");
  script_family("Settings");
  script_dependencies("gb_snmp_sysdescr_detect.nasl", "nmap_mac.nasl", "global_settings.nasl");

  script_add_preference(name:"Exclude PJL printer ports from scan", type:"entry", value:"2000,2501,9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116,9200,10001", id:1);

  script_tag(name:"summary", value:"The host seems to be an AppSocket or socketAPI printer. Scanning
  it will waste paper. So ports 2000, 2501, 9100-9107, 9112-9116, 9200 and 10001 won't be scanned by
  default.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( get_kb_item( "Host/scanned" ) == 0 )
  exit( 0 );

include("host_details.inc");
include("ftp_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("dump.inc");
include("mac_prefix.inc");
include("hp_printers.inc");
include("sharp_printers.inc");
include("kyocera_printers.inc");
include("lexmark_printers.inc");
include("xerox_printers.inc");
include("ricoh_printers.inc");
include("toshiba_printers.inc");
include("epson_printers.inc");
include("canon_printers.inc");
include("snmp_func.inc");
include("pcl_pjl.inc");
include("port_service_func.inc");
include("misc_func.inc");

pjl_ports_list = make_list();

function check_pjl_port_list( list ) {

  local_var list, ports, port;

  if( ! list )
    return FALSE;

  ports = split( list, sep:",", keep:FALSE );

  foreach port( ports ) {

    if( ! ereg( pattern:"^[0-9]{1,5}$", string:port ) ) {
      return FALSE;
    }
    if( int( port ) > 65535 )
      return FALSE;
  }
  return TRUE;
}

function report( data ) {

  local_var data, port;

  pcl_pjl_register_all_ports( ports:pjl_ports_list );
  if( ! invalid_list ) {
    foreach port( pjl_ports_list ) {
      if( get_port_state( port ) ) {
        log_message( port:port, data:"This port was excluded from the scan to avoid printing out paper on this printer during a scan." );
      }
    }
  }

  log_message( port:0, data:'Exclusion reason:\n\n' + data );
  set_kb_item( name:"Host/is_printer/reason", value:data );
  set_kb_item( name:"Host/is_printer", value:TRUE );
  exit( 0 );
}

is_printer = FALSE;

pjl_ports = script_get_preference( "Exclude PJL printer ports from scan", id:1 );
pjl_default_ports_string = pcl_pjl_get_default_ports_string();

if( strlen( pjl_ports ) > 0 ) {
  pjl_ports = str_replace( string:pjl_ports, find:" ", replace:"" );
  if( ! check_pjl_port_list( list:pjl_ports ) ) {
    report = '"Exclude PJL printer ports from scan" has wrong format or contains an invalid port and was ignored. Please use a\ncomma separated list of ports without spaces. Example: ' + pjl_default_ports_string + '\n\n';
    report += 'The following default ports were excluded from the scan to avoid printing out paper on this printer during a scan:\n\n' + pjl_default_ports_string;
    invalid_list = TRUE;
    log_message( port:0, data:report );
    pjl_ports_list = pcl_pjl_get_default_ports();
  } else {
    ports = split( pjl_ports, sep:",", keep:FALSE );
    foreach port( ports ) {
      pjl_ports_list = make_list( pjl_ports_list, port );
    }
  }
} else {
  pjl_ports_list = pcl_pjl_get_default_ports();
}

# First try SNMP on default 161
port = 161;
if( sysdesc = snmp_get_sysdescr( port:port ) ) {

  # Turn hex response into normal string as seen on some Xerox printer
  if( sysdesc =~ "^[0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}" ) {
    sysdesc = hex2str( str_replace( string:sysdesc, find:" ", replace:"" ) );
    sysdesc = bin2string( ddata:sysdesc, noprint_replacement:"" );
  }

  # nb: Keep in sync with the pattern used in gb_xerox_printer_snmp_detect.nasl
  if( sysdesc =~ "^(FUJI )?(Xerox|XEROX) " ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^Canon[^/]+/P" ||
      "Canon LBP" >< sysdesc ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^KYOCERA" && "Print" >< sysdesc ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^Lexmark.+version.+kernel" ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^SHARP [A-Z]{2}-" ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^RICOH" && "RICOH Network Printer" >< sysdesc ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^TOSHIBA e-STUDIO" ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^SATO " ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^KONICA MINOLTA " ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^EPSON " ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^Fiery " ) {
    is_printer = TRUE;
  }

  if( sysdesc =~ "^HP ETHERNET MULTI-ENVIRONMENT" ) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected from SNMP sysDescr OID on port " + port + '/udp:\n\n' + sysdesc );

# Often the printer model is readable over this OID
mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
model = snmp_get( port:port, oid:mod_oid );

if( model ) {

  if( egrep( pattern:"^Xerox", string:model, icase:TRUE ) ) {
    is_printer = TRUE;
  }

  if( model =~ "^Canon[^/]+/P" ||
      "Canon LBP" >< model ) {
    is_printer = TRUE;
  }

  if( model =~ "^KYOCERA" && "Print" >< model ) {
    is_printer = TRUE;
  }

  if( model =~ "^Lexmark" ) {
    is_printer = TRUE;
  }

  if( model =~ "^SHARP [A-Z]{2}-" ) {
    is_printer = TRUE;
  }

  if( model =~ "^RICOH" && "Network Printer" >< model ) {
    is_printer = TRUE;
  }

  if( model =~ "^TOSHIBA e-STUDIO" ) {
    is_printer = TRUE;
  }

  if( model =~ "^SATO " ) {
    is_printer = TRUE;
  }

  if( model =~ "^KONICA MINOLTA " ) {
    is_printer = TRUE;
  }

  if( model =~ "^EPSON " ) {
    is_printer = TRUE;
  }

  if( model =~ "^Fiery " ) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected from SNMP OID '" + mod_oid + "' on port " + port + '/udp:\n\n' + model );

# UDP AppSocket
port = 9101;
if( get_udp_port_state( port ) ) {

  soc = open_sock_udp( port );

  send( socket:soc, data:'\r\n' );
  r = recv( socket:soc, length:512 );
  close( soc );
  if( r ) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected UDP AppSocket on port " + port + '/udp' );

# TBD: Also test all ports of pcl_pjl_get_default_ports()?
# nb: The ( ! r && se == ETIMEDOUT ) might cause false positives here
port = 9100;
if( get_port_state( port ) ) {

  vt_strings   = get_vt_strings();
  pcl_pjl_reqs = pcl_pjl_get_detect_requests( vt_strings:vt_strings );

  foreach pcl_pjl_req( keys( pcl_pjl_reqs ) ) {

    soc = open_sock_tcp( port );
    if( ! soc )
      continue;

    response_check = pcl_pjl_reqs[pcl_pjl_req];

    send( socket:soc, data:pcl_pjl_req );
    r = recv( socket:soc, length:512 );
    se = socket_get_error( soc );
    close( soc );
    if( ( r && response_check >< r ) ||
        ( ! r && se == ETIMEDOUT ) ) {
      is_printer = TRUE;
      break;
    }
  }
}

if( is_printer ) report( data:"Detected Printer Job Language (PJL) / Printer Command Language (PCL) service on port " + port + "/tcp" );

ports = make_list( 9290, 9291, 9292 );

foreach port( ports ) {
  if( ! get_port_state( port ) )
    continue;

  if( ! soc = open_sock_tcp( port ) )
    continue;

  recv = recv( socket:soc, length:16 );
  close( soc );
  if( recv && recv =~ "^0[0-2]$" ) {
    is_printer = TRUE;
    break;
  }
}

if( is_printer ) report( data:"Detected 'Raw scanning to peripherals with IEEE 1284.4 specifications' service on port " + port + "/tcp" );

port = 21;
if( get_port_state( port ) ) {

  banner = ftp_get_banner( port:port );

  if( "JD FTP Server Ready" >< banner ) {
    is_printer = TRUE;
  } else if( "220 Dell Laser Printer " >< banner ) {
    is_printer = TRUE;
  } else if( "220 RICOH" >< banner ) {
    is_printer = TRUE;
  } else if( "220 FTP print service" >< banner ) {
    is_printer = TRUE;
  } else if( "220 KONICA MINOLTA" >< banner ) {
    is_printer = TRUE;
  } else if( "220 Xerox" >< banner ) {
    is_printer = TRUE;
  } else if( "FUJI XEROX" >< banner ) {
    is_printer = TRUE;
  } else if( "Lexmark" >< banner ) {
    is_printer = TRUE;
  } else if( "TOSHIBA e-STUDIO" >< banner ) {
    is_printer = TRUE;
  } else if( " FTP server " >< banner && "(OEM FTPD version" >< banner ) {
    is_printer = TRUE;
  } else if( "EFI FTP Print server" >< banner ) {
    is_printer = TRUE;
  } else if( banner =~ "220 (TASKalfa|ECOSYS)" ) {
    is_printer = TRUE;
  } else if( "220 JD FTP Server Ready" >< banner ) {
    is_printer = TRUE;
  } else if( banner =~ "220 SHARP .*FTP Server" ) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected FTP banner on port " + port + '/tcp:\n\n' + banner );

port = 23;
if( get_port_state( port ) ) {

  banner = telnet_get_banner( port:port );

  if( "HP JetDirect" >< banner ) {
    is_printer = TRUE;
  } else if ("RICOH Maintenance Shell." >< banner) {
    is_printer = TRUE;
  } else if ("Welcome. Type <return>, enter password at # prompt" >< banner) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected Telnet banner on port " + port + '/tcp:\n\n' + banner );

port = 79;
if( get_port_state( port ) ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    send( socket:soc, data:raw_string( 0x0d, 0x0a ) );
    banner = recv( socket:soc, length:512, timeout:5 );
    close( soc );
    if( banner && ( "Printer Type: " >< banner ||
                    "Print Job Status: " >< banner ||
                    "Printer Status: " >< banner ) ) {
      is_printer = TRUE;
    }
  }
}

if( is_printer ) report( data:"Detected Finger banner on port " + port + '/tcp:\n\n' + banner );

# Xerox DocuPrint
port = 2002;
if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( soc ) {
    banner = recv( socket:soc, length:23 );
    close( soc );
    if( banner && 'Please enter a password' >< banner ) {
      is_printer = TRUE;
    }
  }
}

if( is_printer ) report( data:"Detected Xerox DocuPrint banner on port " + port + '/tcp:\n\n' + banner );

if( mac = get_kb_item( "Host/mac_address" ) ) {
  if( is_printer_mac( mac:mac ) )
    is_printer = TRUE;
}

if( is_printer ) report( data:"Detected MAC-Address of a Printer vendor: " + mac );

ports = make_list( 9220, 9221, 9222 );

foreach port( ports ) {
  if( ! get_port_state( port ) )
    continue;

  if( ! soc = open_sock_tcp( port ) )
    continue;

  banner = recv( socket:soc, length:512 );
  close( soc );
  if( banner && egrep( string:banner, pattern:"^220 (HP|JetDirect) GGW server \(version ([0-9.]+)\) ready" ) ) {
    is_printer = TRUE;
    break;
  }
}

if( is_printer ) report( data:"Detected Generic Scan Gateway (GGW) server service on port " + port + '/tcp:\n\n' + chomp( banner ) );

# nb: Keep the HTTP check at the bottom as this can take quite some time

# nb: For the HTTPS detection these pattern needs to be updated
# as those redirects only happen on HTTP.
konica_detect_urls = make_array();
konica_detect_urls['/wcd/top.xml'] = "^HTTP/1\.[01] 301 Movprm";
konica_detect_urls['/wcd/system_device.xml'] = "^HTTP/1\.[01] 301 Movprm";
konica_detect_urls['/wcd/system.xml'] = "^HTTP/1\.[01] 301 Movprm";

ports = make_list( 80, 8000, 280, 631 ); # TODO: Re-add 443 and add 8443 once a solution was found to detect SSL/TLS without a dependency to find_service.nasl

foreach port( ports ) {

  if( ! get_port_state( port ) )
    continue;

  # Sharp can be detected from the start page, see also gb_sharp_printer_http_detect.nasl
  # If updating here please also update check gb_sharp_printer_http_detect.nasl
  buf = http_get_cache( item:"/", port:port );
  if( buf && buf =~ "^HTTP/1\.[01] 200" && ( "Extend-sharp-setting-status" >< buf || "Server: Rapid Logic" >< buf ) ) {

    urls = get_sharp_detect_urls();
    foreach url( keys( urls ) ) {

      pattern = urls[url];
      url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

      buf = http_get_cache( item:url, port:port );
      if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
        continue;

      if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
        is_printer = TRUE;
        reason     = "Sharp Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }
  }

  # Brother HL Printer from gb_brother_hl_series_printer_detect.nasl
  # If updating here please also update the check in gb_brother_hl_series_printer_detect.nasl
  url = "/general/information.html?kind=item";
  buf = http_get_cache( item:url, port:port );
  if( buf =~ "<title>Brother HL.*series</title>" && buf =~ "Copyright.*Brother Industries" ) {
    is_printer = TRUE;
    reason     = "Brother Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }

  # SATO, see also gb_sato_printer_http_detect.nasl
  # If updating here please also update the check in gb_sato_printers_http_detect.nasl
  url = "/WebConfig/";
  buf = http_get_cache( item:url, port:port );
  if( "<title>SATO Printer Setup</title>" >< buf ) {
    is_printer = TRUE;
    reason     = "SATO Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }

  # Konica Minolta, more detailed detection in gsf/gb_konicaminolta_printer_http_detect.nasl
  foreach url( keys( konica_detect_urls ) ) {

    pattern = konica_detect_urls[url];

    buf = http_get_cache( item:url, port:port );
    if( ! buf )
      continue;

    if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # HP, see also gb_hp_printer_http_detect.nasl
  urls = get_hp_detect_urls();
  foreach url( keys( urls ) ) {

    pattern = urls[url];
    url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
      continue;

    if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  banner = http_get_remote_headers( port:port );

  # Kyocera, see also gb_kyocera_printer_http_detect.nasl
  # e.g.:
  # Server: KM-MFP-http/V0.0.1
  # nb: Keep in sync with gb_kyocera_printer_http_detect.nasl and sw_http_os_detection.nasl

  if( concl = egrep( pattern:"^Server\s*:\s*KM-MFP-http", string:banner, icase:TRUE ) ) {
    concl      = chomp( concl );
    is_printer = TRUE;
    reason     = "Kyocera banner: " + concl;
    break;
  } else {
    urls = kyocera_get_detect_urls();
    foreach url( keys( urls ) ) {

      pattern = urls[url];
      url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

      buf = http_get_cache( item:url, port:port );
      if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
        continue;

      if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
        is_printer = TRUE;
        reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }
  }

  if( is_printer ) break;

  # Lexmark, see also gb_lexmark_printer_http_detect.nasl
  urls = get_lexmark_detect_urls();
  foreach url( keys( urls ) ) {

    pattern = urls[url];
    url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
      continue;

    if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # Xerox, see also gb_xerox_printer_http_detect.nasl
  urls = get_xerox_detect_urls();
  foreach url( keys( urls ) ) {

    pattern = urls[url];
    url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

    buf = http_get_cache( item:url, port:port );
    if( ! buf || ( buf !~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 401" ) )
      continue;

    # Replace non-printable characters to avoid language based false-negatives
    buf = bin2string( ddata:buf, noprint_replacement:"" );
    if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }

    # nb: See bottom of gb_xerox_printer_detect.nasl
    if( buf =~ "^HTTP/1\.[01] 401" && "CentreWare Internet Services" >< buf ) {
      is_printer = TRUE;
      reason     = "Found pattern: CentreWare Internet Services on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # Ricoh, see also gb_ricoh_printer_http_detect.nasl
  urls = get_ricoh_detect_urls();
  foreach url( keys( urls ) ) {

    pattern = urls[url];
    url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
      continue;

    if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # Toshiba, see also gb_toshiba_printer_http_detect.nasl
  urls = get_toshiba_detect_urls();
  foreach url( keys( urls ) ) {

    pattern = urls[url];
    url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
      continue;

    if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  # EFI Fiery, see also gb_efi_fiery_http_detect.nasl
  url = "/wt4/home";
  res = http_get_cache( port:port, item:url );

  if( "<title>WebTools" >< res && "id-footer-efi-logo" >< res ) {
    is_printer = TRUE;
    reason     = "EFI Fiery Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  } else {
    url = "/wt2parser.cgi?home_en";
    res = http_get_cache( port:port, item:url );

    if( "<title>Webtools" >< res && '<span class="footertext">&copy; EFI' >< res &&
        "wt2parser.cgi?status_en.htm" >< res ) {
      is_printer = TRUE;
      reason     = "EFI Fiery Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  if( is_printer ) break;

  # Epson, see also gb_epson_printer_http_detect.nasl
  # e.g.:
  # SERVER: EPSON_Linux UPnP/1.0 Epson UPnP SDK/1.0
  # Server: EPSON HTTP Server
  # Server: EPSON-HTTP/1.0
  # nb: Note that the "Epson UPnP SDK" shouldn't use a "^"
  # nb: Keep in sync with gb_epson_printer_http_detect.nasl and sw_http_os_detection.nasl
  if( concl = egrep( pattern:"(^SERVER\s*:\s*(EPSON_Linux|EPSON HTTP Server|EPSON-HTTP)|Epson UPnP SDK)", string:banner, icase:TRUE ) ) {
    concl      = chomp( concl );
    is_printer = TRUE;
    reason     = "Epson banner: " + concl;
    break;
  } else {
    urls = get_epson_detect_urls();
    foreach url( keys( urls ) ) {
      pattern = urls[url];
      url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

      buf = http_get_cache( item:url, port:port );
      if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
        continue;

      if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
        is_printer = TRUE;
        reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }
  }

  # Canon, see also gb_canon_printer_http_detect.nasl
  # e.g.:
  # Server: KS_HTTP/1.0
  # Server: CANON HTTP Server
  # Server: Catwalk
  # nb: Keep in sync with gb_canon_printer_http_detect.nasl and sw_http_os_detection.nasl
  if( concl = egrep( pattern:"^Server\s*:\s*(KS_HTTP|CANON HTTP Server|Catwalk)", string:banner, icase:TRUE ) ) {
    concl      = chomp( concl );
    is_printer = TRUE;
    reason     = "Canon banner: " + concl;
    break;
  } else {
    urls = get_canon_detect_urls();
    foreach url( keys( urls ) ) {
      pattern = urls[url];
      url = ereg_replace( string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"" );

      buf = http_get_cache( item:url, port:port );
      if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
        continue;

      if( eregmatch( pattern:pattern, string:buf, icase:TRUE ) ) {
        is_printer = TRUE;
        reason     = "Found pattern: " + pattern + " on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }
  }

  # TODO: Re-verify these URLs and the banners below
  foreach url( make_list( "/", "/main.asp", "/index.asp",
                          "/index.html", "/index.htm", "/default.html" ) ) {

    buf = http_get_cache( item:url, port:port );

    # Dell
    if( "Dell Laser Printer " >< banner || "Server: EWS-NIC5/" >< banner || "Dell Laser MFP " >< banner ) {
      is_printer = TRUE;
      reason     = "Dell Banner on port " + port + "/tcp: " + banner;
      break;
    # TBD: unknown printers. Ricoh?
    } else if( banner && "Server: GoAhead-Webs" >< banner && "Aficio SP" >< banner || "<title>Web Image Monitor</title>" >< banner ) {
      is_printer = TRUE;
      reason     = "Printer Banner on port " + port + "/tcp: " + banner;
      break;
    # Old HP banner check
    } else if( "<title>Hewlett Packard</title>" >< buf || egrep( pattern:"<title>.*LaserJet.*</title>", string:buf, icase:TRUE ) ||
               "HP Officejet" >< buf || "server: hp-chai" >< tolower( buf ) || ( "Server: Virata-EmWeb/" >< buf && ( "HP" >< banner || "printer" >< buf ) ) ) {
      is_printer = TRUE;
      reason     = "HP Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    # Old Xerox banner check
    } else if( "Server: Xerox_MicroServer/Xerox" >< buf || "Server: EWS-NIC" >< buf || "<title>DocuPrint" >< buf || "<title>Phaser" >< buf ||
               ( "XEROX WORKCENTRE" >< buf && "Xerox Corporation. All Rights Reserved." >< buf ) || ( "DocuCentre" >< buf && "Fuji Xerox Co., Ltd." >< buf ) ) {
      is_printer = TRUE;
      reason     = "Xerox Banner/Text on URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }
  if( is_printer ) break;
}

if( is_printer ) report( data:reason );

exit( 0 );

# TBD if the following should be still used
#
# open ports?
#ports = get_kb_list("Ports/tcp/*");
#
# Host is dead, or all ports closed, or unscanned => cannot decide
#if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4981.htm
#appsocket = 0;
#
#foreach p (keys(ports))
#{
#  p = int(p - "Ports/tcp/");
#  if (    p == 35                  # AppSocket for QMS
#       || p == 2000                # Xerox
#       || p == 2501                # AppSocket for Xerox
#       || (p >= 3001 && p <= 3005) # Lantronix - several ports
#       || (p >= 9100 && p <= 9300) # AppSocket - several ports
#       || p == 10000               # Lexmark
#       || p == 10001)              # Xerox - programmable :-(
#    appsocket = 1;
# Look for common non-printer ports
#        else if (
#          p != 21              # FTP
#       && p != 23              # telnet
#       && p != 79
#       && p != 80              # www
#       && p != 139 && p!= 445  # SMB
#       && p != 280             # http-mgmt
#       && p != 443
#       && p != 515             # lpd
#       && p != 631            # IPP
#       && p != 8000
#       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers
#       exit(0);
#
#}
#
# OK, this might well be an AppSocket printer
#if (appsocket)
#{
#  log_message(0);
#
#  service_register(port: 9100, proto: "ignore-this-printer-port");
#
#  #set_kb_item( name:"Host/dead", value:TRUE );
#}
