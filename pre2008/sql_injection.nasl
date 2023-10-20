# SPDX-FileCopyrightText: 2002 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11139");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Generic HTTP SQLi (Web Application) - Active Check");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2002 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"http://en.wikipedia.org/wiki/SQL_injection");
  script_xref(name:"URL", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html");
  script_xref(name:"URL", value:"http://www.securitydocs.com/library/2651");

  script_tag(name:"summary", value:"This script attempts to use SQL injection (SQLi) techniques on
  CGI / web application scripts.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP requests and checks the
  responses.");

  script_tag(name:"insight", value:"NOTE: Please enable 'Enable generic web application scanning'
  within the preferences of the VT 'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) if
  you want to run this script.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to bypass authentication or to
  take the control of the remote database.");

  script_tag(name:"solution", value:"Modify the relevant CGIs so that they properly escape
  arguments.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

# TODO: Create a separate "reporting" VT which reports found items
# by this VT if it reached a timeout or exit(0) was used due to the failed requests.

# nb: We also don't want to run if optimize_test is set to "no"
if( http_is_cgi_scan_disabled() ||
    get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

single_quote = raw_string(0x27);

poison[0] = single_quote + "UNION" + single_quote;
poison[1] = single_quote;
poison[2] = single_quote + "%22";
poison[3] = "9%2c+9%2c+9";
poison[4] = single_quote + "bad_bad_value";
poison[5] = "bad_bad_value" + single_quote;
poison[6] = single_quote + "+OR+" + single_quote;
poison[7] = single_quote + "WHERE";
poison[8] = "%3B"; # semicolon
poison[9] = single_quote + "OR";
# methods below from http://www.securiteam.com/securityreviews/5DP0N1P76E.html
poison[10] = single_quote + " or 1=1--";
poison[11] = " or 1=1--";
poison[12] = single_quote + " or " + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[13] = single_quote + ") or (" + single_quote + "a" + single_quote + "=" + single_quote + "a";

# blind sql injection methods that we will pass
# if they are putting the user-supplied variable within single quotes, then we trick them with this
blinder[0] = single_quote + "+AND+" + single_quote + "a" + single_quote + ">" + single_quote + "b";
# otherwise, this will work most of the time
blinder[1] = "+AND+1=1";

posreply[0] = "Can't find record in";
posreply[1] = "Column count doesn't match value count at row";
posreply[2] = "error " + single_quote;
posreply[3] = "Incorrect column name";
posreply[4] = "Incorrect column specifier for column";
posreply[5] = "Invalid parameter type";
posreply[6] = "Microsoft OLE DB Provider for ODBC Drivers error";
posreply[7] = "ODBC Microsoft Access Driver";
posreply[8] = "ODBC SQL Server Driver";
posreply[9] = "supplied argument is not a valid MySQL result";
posreply[10] = "mysql_query()";
posreply[11] = "Unknown table";
posreply[12] = "You have an error in your SQL syntax";
posreply[13] = "Error Occurred While Processing Request";
posreply[14] = "Syntax error converting the varchar value";
posreply[15] = "not a valid MySQL result resource";
posreply[16] = "unexpected end of SQL command";
posreply[17] = "mySQL error with query";
posreply[18] = "ORA-00936: missing expression";
posreply[19] = "ORA-00933: SQL command not properly ended";
posreply[20] = "Unclosed quotation mark before the character string";
posreply[21] = "Incorrect syntax near";
posreply[22] = "PostgreSQL query failed:";
posreply[23] = "not a valid PostgreSQL result";
posreply[24] = "An illegal character has been found in the statement";
posreply[25] = "[IBM][CLI Driver][DB2/6000]";
posreply[26] = "Unable to connect to PostgreSQL server:";
posreply[27] = "Can't connect to local";
posreply[28] = "ADODB.Recordset";
posreply[29] = "Microsoft SQL Native Client error";
posreply[30] = "Query failed: ERROR: syntax error at or near";

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

unsafe_urls = "";
blind_urls = "";
mywarningcount = 0;
blindwarningcount = 0;

cgis = http_get_kb_cgis( port:port, host:host );
if( ! cgis ) exit( 0 );

foreach cgi( cgis ) {

  # populate two arrays param[] and data[]
  everythingrray = split( cgi, sep:" ", keep:FALSE );

  if( everythingrray[0] =~ ".*/$") {
    isdir = TRUE;
  } else {
    isdir = FALSE;
  }

  #counter for current failed requests
  failedReqs = 0;
  #counter for max failed requests
  #The VT will exit if this is reached
  #TBD: Make this configurable?
  maxFailedReqs = 5;

  if( ! isdir ) {
    vrequest = string( everythingrray[0], "?" );
    bogus_vrequest = string( everythingrray[0], "?", rand() );
    pseudocount = 0;
    foreach rrayval( everythingrray ) {
      if( pseudocount >= 2 ) {
        if( "]" >< rrayval ) {
          pseudocount--;
          tmpf = ereg_replace( pattern:"\[|\]", string:rrayval, replace:"" );
          data[pseudocount] = tmpf;
          vrequest = string( vrequest, "=", tmpf );
        } else {
          param[pseudocount] = rrayval;
          if( pseudocount == 2 ) {
            vrequest = string( vrequest, rrayval );
          } else {
            vrequest = string( vrequest, "&", rrayval );
          }
        }
      } else {
        param[pseudocount] = rrayval;
      }
      pseudocount++;
    }
  }

  for( z = 2; param[z]; z++ ) {

    blind = '';
    url = vrequest;
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( ( isnull( res ) ) || ( ! egrep( string:res, pattern:"^HTTP/1\.[01] (200|302)" ) ) ) {
      failedReqs++;
      if( failedReqs >= maxFailedReqs ) {
        exit( 0 );
      }
      continue;
    }

    if( "Content-Length: 0" >< res ) continue; # there is no body to compare later. dell omsa fp workaround

    res_saved = strstr( res, string( "\r\n\r\n" ) );
    req = http_get( item:bogus_vrequest, port:port );
    bres = http_keepalive_send_recv( port:port, data:req );

    if( egrep( string:bres, pattern:"^HTTP/1\.[01] 200" ) ) {
      continue;
    }

    for( i = 0; posreply[i]; i++ ) {
      if( posreply[i] >< res ) {
        exit( 0 );
      }
    }

    for( poo = 0; poison[poo]; poo++ ) {

      doblind = 0;
      qa = '';
      url = string( param[0], "?" );
      blind = string( param[0], "?" );
      for( i = 2; param[i]; i++ ) {
        if( i == z ) {
          if( blinder[poo] ) {
            doblind++;
            qa = string( blind, param[i], "=", data[i], "'" );
            blind = string( blind, param[i], "=", data[i], blinder[poo] );
          }

          if (data[i]) {
            url = string( url, param[i], "=", poison[poo] );
          } else {
            url = string( url, param[i], "=", poison[poo] );
          }
        } else {
          if( blinder[poo] ) {
            qa = string( qa, param[i], "=", data[i] );
            blind = string( blind, param[i], "=", data[i] );
          }

          if( data[i] ) {
            url = string( url, param[i], "=", data[i] );
          } else {
            url = string( url, param[i], "=" );
          }
        }

        if( param[i + 1] ) {
          url = string( url, "&" );
          blind = string( blind, "&" );
          qa = string( qa, "&" );
        }
      }

      req = http_get( item:url, port:port );
      inbuff = http_keepalive_send_recv( port:port, data:req );

      if( isnull( inbuff ) ) {
        failedReqs++;
        if( failedReqs >= maxFailedReqs ) {
          exit( 0 );
        }
        continue;
      }

      if( "Content-Length: 0" >< inbuff ) continue;

      for( mu = 0; posreply[mu]; mu++ ) {
        if( posreply[mu] >< inbuff ) {
          unsafe_urls = string( unsafe_urls, http_report_vuln_url( port:port, url:url, url_only:TRUE ), ":", posreply[mu], "\n" );
          mywarningcount++;
        }
      }

      if( doblind > 0 ) {

        req_blind = http_get( item:blind, port:port );
        inbuff = http_keepalive_send_recv( port:port, data:req_blind );

        if( isnull( inbuff ) ) {
          failedReqs++;
          if( failedReqs >= maxFailedReqs ) {
            exit( 0 );
          }
          continue;
        }

        if( "Content-Length: 0" >< inbuff ) continue;

        buff_body = strstr( inbuff, string( "\r\n\r\n" ) );
        if( buff_body == res_saved ) {
          req_qa = http_get( item:qa, port:port );
          inbuff = http_keepalive_send_recv( port:port, data:req_qa );
          qa_body = strstr( inbuff, string( "\r\n\r\n" ) );

          if( "Content-Length: 0" >< inbuff ) continue;

          if( qa_body != res_saved ) {
            blind_urls = string( blind_urls, http_report_vuln_url( port:port, url:blind, url_only:TRUE ), "\n" );
            blindwarningcount++;
          }
        }
      }

      if( safe_checks() == 0 ) {

        # create a POST req
        tmppost = split( url, sep:"?", keep:FALSE );
        mypostdata = tmppost[1];
        postreq = http_post( item:param[0], port:port, data:mypostdata );

        # Test the POST req
        inbuff = http_keepalive_send_recv( port:port, data:postreq );
        if( isnull( inbuff ) ) {
          failedReqs++;
          if( failedReqs >= maxFailedReqs ) {
            exit( 0 );
          }
          continue;
        }

        if( "Content-Length: 0" >< inbuff ) continue;

        for( mu = 0; posreply[mu]; mu++ ) {
          if( posreply[mu] >< inbuff ) {
            unsafe_urls = string( unsafe_urls, http_report_vuln_url( port:port, url:url, url_only:TRUE ), ":", posreply[mu], "\n" );
            mywarningcount++;
          }
        }

        if( doblind > 0 ) {

          # create a blind POST req
          tmppost = split( blind, sep:"?", keep:FALSE );
          mypostdata = tmppost[1];
          postreq = http_post( item:param[0], port:port, data:mypostdata );

          inbuff = http_keepalive_send_recv( port:port, data:postreq );
          if( isnull( inbuff ) ) {
            failedReqs++;
            if( failedReqs >= maxFailedReqs ) {
              exit( 0 );
            }
            continue;
          }

          if( "Content-Length: 0" >< inbuff ) continue;

          buff_body = strstr( inbuff, string( "\r\n\r\n" ) );

          if( buff_body == res_saved ) {
            qapost = split( blind, sep:"?", keep:FALSE );
            qapostdata = tmppost[1];
            qareq = http_post( item:param[0], port:port, data:qapostdata );
            qabuff = http_keepalive_send_recv( port:port, data:qareq );
            qa_body = strstr( qabuff, string( "\r\n\r\n" ) );

            if( qa_body != res_saved ) {
              blind_urls = string( blind_urls, http_report_vuln_url( port:port, url:blind, url_only:TRUE ), "\n" );
              blindwarningcount++;
            }
          }
        }
      }
      # end the non-safe check
    }
  }
}

report = "";

if( mywarningcount > 0 ) {
  VULN = TRUE;
  report += string( "The following URLs seem to be vulnerable to various SQL injection techniques : <url>:<matching pattern>\n\n", unsafe_urls, "\n\n" );
}

if( blindwarningcount > 0 ) {
  VULN = TRUE;
  report += string( "The following URLs seem to be vulnerable to BLIND SQL injection techniques : \n\n", blind_urls, "\n\n" );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
