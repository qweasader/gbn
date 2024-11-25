# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108099");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-03-15 11:00:00 +0100 (Wed, 15 Mar 2017)");
  script_name("SSL/TLS: NPN / ALPN Extension and Protocol Support Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7301");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04");

  script_tag(name:"summary", value:"This routine identifies services supporting the following extensions to TLS:

  - Application-Layer Protocol Negotiation (ALPN)

  - Next Protocol Negotiation (NPN).

  Based on the availability of this extensions the supported Network Protocols by this service are gathered and reported.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("mysql.inc");
include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");

# Passed to read_ssl_record() of ssl_funcs.inc
global_var alpn_prot;

npn_report_header  = 'The remote service advertises support for the following Network Protocol(s) via the NPN extension:\n\nSSL/TLS Protocol:Network Protocol\n';
alpn_report_header = 'The remote service advertises support for the following Network Protocol(s) via the ALPN extension:\n\nSSL/TLS Protocol:Network Protocol\n';
npn_report_list    = make_list();
alpn_report_list   = make_list();

port = http_get_port( default:443, ignore_broken:TRUE, ignore_cgi_disabled:TRUE );

## Exit on non-ssl http port
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

if( ! versions = get_supported_tls_versions( port:port, min:SSL_v3 ) ) exit( 0 );

# First check for NPN
foreach version( versions ) {

  if( ! SSL_VER = version_kb_string_mapping[version] ) continue;

  hello_done = FALSE;

  soc = open_ssl_socket( port:port );
  if( ! soc ) continue;

  hello = ssl_hello( port:port, version:version, extensions:make_list( "next_protocol_negotiation" ) );
  if( ! hello ) {
    close( soc );
    continue;
  }

  send( socket:soc, data:hello );

  while( ! hello_done ) {

    data = ssl_recv( socket:soc );

    if( ! data ) {
      close( soc );
      break;
    }

    # Jump out if we're getting an ALERT
    record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
    if( record ) {
      close( soc );
      break;
    }

    record = search_ssl_record( data:data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
    if( record ) {

      npn_prots = record['extension_npn_supported_protocols'];

      # Just to make sure that we're getting what we're expecting
      if( npn_prots ) {

        # The server will report all supported protocols via NPN
        foreach npn_prot( npn_prots ) {
          npn_supported = TRUE;
          if( npn_alpn_name_mapping[npn_prot] )
            npn_report_list = make_list( npn_report_list, version_string[version] + ":" + npn_alpn_name_mapping[npn_prot] );
          else
            npn_report_list = make_list( npn_report_list, version_string[version] + ":" + npn_prot + " (missing/unknown mapping, please report this to https://forum.greenbone.net/c/vulnerability-tests/7)" );
          set_kb_item( name:"tls_npn_supported/" + SSL_VER + "/" + port, value:TRUE );
          set_kb_item( name:"tls_npn_prot_supported/" + SSL_VER + "/" + port, value:npn_prot );
        }
      }
    }

    record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
    if( record ) {
      hello_done = TRUE;
      break;
    }
  }
}

# Next check for ALPN
foreach version( versions ) {

  if( ! SSL_VER = version_kb_string_mapping[version] ) continue;

  foreach alpn_prot( npn_alpn_protocol_list ) {

    hello_done = FALSE;

    soc = open_ssl_socket( port:port );
    if( ! soc ) continue;

    hello = ssl_hello( port:port, version:version, extensions:make_list( "application_layer_protocol_negotiation"  ), alpn_protocol:alpn_prot );
    if( ! hello ) {
      close( soc );
      continue;
    }

    send( socket:soc, data:hello );

    while( ! hello_done ) {

      data = ssl_recv( socket:soc );

      if( ! data ) {
        close( soc );
        break;
      }

      # Jump out if we're getting an ALERT
      record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
      if( record ) {
        close( soc );
        break;
      }

      record = search_ssl_record( data:data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
      if( record ) {
        alpn_prots = record['extension_alpn_supported_protocols'];

        # Just to make sure that we're getting what we're expecting
        if( alpn_prots ) {

          # Sort to make sure that we're not reporting differences on delta reports if just the order is different
          alpn_prots = sort( alpn_prots );

          # The server will choose only one protocol via ALPN, still iterating over the list here...
          foreach alpn_prot( alpn_prots ) {
            alpn_supported = TRUE;
            alpn_report_list = make_list( alpn_report_list, version_string[version] + ":" + npn_alpn_name_mapping[alpn_prot] );
            set_kb_item( name:"tls_alpn_supported/" + SSL_VER + "/" + port, value:TRUE );
            set_kb_item( name:"tls_alpn_prot_supported/" + SSL_VER + "/" + port, value:alpn_prot );
          }
        }
      }

      record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
      if( record ) {
        hello_done = TRUE;
        break;
      }
    }
  }
}

if( alpn_supported || npn_supported ) {
  if( npn_supported ) {
    # Sort to make sure that we're not reporting differences on delta reports if just the order is different
    npn_report_list = sort( npn_report_list );
    report += npn_report_header;
    foreach npn_report( npn_report_list ) {
      report += npn_report + '\n';
    }
  }

  if( alpn_supported && npn_supported ) report += '\n';

  if( alpn_supported ) {
    # Sort to make sure that we're not reporting differences on delta reports if just the order is different
    alpn_report_list = sort( alpn_report_list );
    report += alpn_report_header;
    foreach alpn_report( alpn_report_list ) {
      report += alpn_report + '\n';
    }
  }

  log_message( port:port, data:report );
}

exit( 0 );
