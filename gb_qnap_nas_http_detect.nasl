# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103875");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2014-01-09 18:50:23 +0100 (Thu, 09 Jan 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("QNAP NAS / QTS / QES / QuTS Hero / QuTSCloud Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of QNAP NAS devices and the QTS / QES /
  QuTS Hero / QuTSCloud operating systems.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

port = http_get_port( default:8080 );

host = http_host_name( port:port );
useragent = http_get_user_agent();

foreach url( make_list( "/cgi-bin/login.html", "/cgi-bin/html/login.html" , "/cgi-bin/authLogin.cgi" ) ) {

  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! res || "<title>Welcome to QNAP Turbo NAS" >!< res )
    continue;

  is_os = FALSE;
  os_flavor = "";
  os_string = "";
  concluded = "";

  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( "QTS_REMEMBER_ME" >< res || "QTS_SSL_LOGIN" >< res ) {

    #<link rel="stylesheet" href="/cgi-bin/loginTheme/theme1/login.css?r=form&1601932357" type="text/css" media="screen"/>
    if( '<link rel="stylesheet" href="/cgi-bin/loginTheme/theme1/login.css' >< res ) {

      url3 = "/cgi-bin/loginTheme/theme1/login.css";
      req3 = http_get( item:url3, port:port );
      css_buf = http_send_recv( port:port, data:req3, bodyonly:FALSE );
      #.version .fw-ver:before{content:"QTS "
      #.version .fw-ver:before {
      #content: "QES "
      # This check would only distinguish between QES and QTS, QuTS Hero would be also determined as QTS. But we solve that version-based
      # as QuTS version is always prefixed by h
      # The initial idea to check for the qts-zsf .css class to determine QuTS Hero here seems overly-complex
      os_type_str1 = eregmatch( pattern:'[.]version [.]fw-ver[:]before[ ]*[{][\r\n\t ]*content[:][ ]*"([A-Za-z0-9 ]+) "', string:css_buf );
      if( ! isnull( os_type_str1[1] ) ) {
        # here the value would be either QTS or QES
        conclUrl += '\n' + http_report_vuln_url( port:port, url:url3, url_only:TRUE );
        concluded = os_type_str1[0];
        is_os = TRUE;
        os_string = os_type_str1[1];
        os_flavor = tolower( os_string );
      } else {
        # in case of QTS that CSS class seems to be missing
        is_os = TRUE;
        os_string = "QTS";
        os_flavor = "qts";
      }

    } else {
      #leave this as a fallback case to QTS, for older versions
      is_os = TRUE;
      os_string = "QTS";
      os_flavor = "qts";
    }
  }

  url2 = "/cgi-bin/authLogin.cgi";
  headers = make_array( "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Content-Type", "application/x-www-form-urlencoded" );
  req = http_post_put_req( port:port, url:url2, data:"&r=0", add_headers:headers, referer_url:url );
  res = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! res || "QDocRoot" >!< res )
    continue;

  set_kb_item( name:"qnap/nas/detected", value:TRUE );
  set_kb_item( name:"qnap/nas/http/detected", value:TRUE );

  version = "unknown";
  build = "unknown";
  model = "Unknown model";
  install = "/";
  conclUrl += '\n' + http_report_vuln_url( port:port, url:url2, url_only:TRUE );

  # QTS: <version><![CDATA[4.4.1]]></version>
  # QuTS Hero: <version><![CDATA[h5.0.0]]></version>
  # QuTSCloud: <version><![CDATA[c5.0.0]]></version>
  # QES: <version><![CDATA[2.2.0.1053]]></version>
  vers = eregmatch( pattern:"<version><!\[CDATA\[([^]]+)\]\]></version>", string:res );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    # Due to the fact that QuTS Hero login.css style is similar to the QTS one,
    # we use the fact that QuTS Hero version always starts with h
    # <version><![CDATA[h4.5.0]]></version>
    # versus QTS where it is like
    # <version><![CDATA[4.3.3]]></version>
    check_vers = eregmatch( pattern:"(h[A-Za-z0-9.]+)", string:version );

    if( ! isnull( check_vers[1] ) ) {
      os_string = "QuTS Hero";
      os_flavor = "quts_hero";
    }

    # Also, QuTSCloud version starts with c
    # <version><![CDATA[c5.0.0]]></version>
    check_vers = eregmatch( pattern:"(c[A-Za-z0-9.]+)", string:version );

    if ( ! isnull( check_vers[1] ) ) {
      is_os = TRUE;
      os_flavor = "qutscloud";
      os_string = "QuTScloud";
    }
    if( concluded )
      concluded += '\n';
    concluded += vers[0];
  } else {
    # nb: Older versions
    # version>3.1.1</version>
    vers = eregmatch( pattern:"<version>([a-z0-9.]+)</version>", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      if( concluded )
        concluded += '\n';
      concluded += vers[0];
      is_os = TRUE;
      os_string = "QTS";
      os_flavor = "qts";
    }
  }

  # <number><![CDATA[1448]]></number>
  nr = eregmatch( pattern:"<number><!\[CDATA\[([^]]+)\]\]></number>", string:res );
  if( ! isnull( nr[1] ) ) {
    version += "." + nr[1];
    if( concluded )
      concluded += '\n';
    concluded += nr[0];
  }

  # <build><![CDATA[20191206]]></build>
  # <build><![CDATA[20220324]]></build>
  bld = eregmatch( pattern:"<build><!\[CDATA\[([^]]+)\]\]></build>", string:res );
  if( ! isnull( bld[1] ) ) {
    build = bld[1];
    if( concluded )
      concluded += '\n';
    concluded += bld[0];
  }
  # nb: displayModelName is actually the model name, when this value is different from modelName
  # <displayModelName><![CDATA[TS-453A]]></displayModelName>
  # QuTSCloud: <displayModelName><![CDATA[QuTScloud]]></displayModelName>
  # <displayModelName><![CDATA[ES1686dc]]></displayModelName>
  displaymod = eregmatch( pattern:"<displayModelName><!\[CDATA\[([^]]+)\]\]></displayModelName>", string:res );
  if( ! isnull( displaymod[1] ) ) {
    model = displaymod[1];

    if( concluded )
      concluded += '\n';
    concluded += displaymod[0];
    # For QuTSCloud it looks like this tag always has the value QuTScloud
    # <displayModelName><![CDATA[QuTScloud]]></displayModelName>
    if( "QuTScloud" >< displaymod[1] ) {
      os_string = displaymod[1];
      is_os = TRUE;
      os_flavor = "qutscloud";
    }
  }


  # nb: It seems that in some cases <modelName> contains the name of the series, not the model
  # <modelName><![CDATA[TS-X53II]]></modelName>
  # <modelName><![CDATA[TS-X73A]]></modelName>
  # QuTSCloud: <modelName><![CDATA[TS-KVM-CLD]]></modelName>
  # QES: <modelName><![CDATA[ES1686dc]]></modelName>
  mod = eregmatch( pattern:"<modelName><!\[CDATA\[([^]]+)\]\]></modelName>", string:res );
  if( ! isnull( mod[1] ) ) {
    if ( model == "Unknown model")
      model = mod[1];
    if( concluded )
      concluded += '\n';
    concluded += mod[0];
  } else {
    # <modelName>TS-219P</modelName>
    mod = eregmatch( pattern:"<modelName>([^<]+)</modelName>", string:res );
    if( ! isnull( mod[1] ) ) {
      if ( model == "Unknown model")
        model = mod[1];
      if( concluded )
        concluded += '\n';
      concluded += mod[0];
    }
  }

  report = "";

  if( is_os ) {

    os_cpe = "cpe:/o:qnap:" + os_flavor;
    set_kb_item( name:"qnap/nas/" + os_flavor + "/detected", value:TRUE );
    set_kb_item( name:"qnap/nas/" + os_flavor + "/http/detected", value:TRUE );

    if( version != "unknown" )
      os_cpe += ":" + version;

    set_kb_item( name:"qnap/nas/os_name", value:os_string );
    os_register_and_report( os:"QNAP " + os_string, cpe:os_cpe, banner_type:"HTTP(s) Login Page", port:port, desc:"QNAP NAS / QTS / QES / QuTS Hero / QuTSCloud Detection (HTTP)", runs_key:"unixoide" );
    register_product( cpe:os_cpe, location:install, port:port, service:"www" );
    report  = build_detection_report( app:"QNAP " + os_string, version:version, build:build, install:install, cpe:os_cpe );
  }

  set_kb_item( name:"qnap/nas/model", value:model );
  set_kb_item( name:"qnap/nas/" + os_flavor + "/version", value:version );
  set_kb_item( name:"qnap/nas/" + os_flavor + "/build", value:build );
  set_kb_item( name:"qnap/nas/port", value:port );

  cpe_model = tolower( str_replace( string:model, find:" ", replace:"_" ) );

  if ( cpe_model != "qutscloud" ) {
    hw_cpe = "cpe:/h:qnap";

    hw_cpe += ":" + cpe_model;

    register_product( cpe:hw_cpe, location:install, port:port, service:"www" );
    if ( report )
      report += '\n\n';
    report += build_detection_report( app:"QNAP " + model, install:install, cpe:hw_cpe, skip_version:TRUE );
  }

  extra += 'HTTP(s) on port ' + port + '/tcp';
  if( concluded )
    extra += '\n  Concluded from version/product identification result:\n' + concluded + '\n';

  if( conclUrl )
    extra += '\n  Concluded from version/product identification location:\n' + conclUrl + '\n';

  if( extra ) {
    report += '\n\nDetection methods:\n';
    report += '\n' + extra;
  }

  log_message( port:port, data:chomp( report ) );

  exit( 0 );
}

exit( 0 );
