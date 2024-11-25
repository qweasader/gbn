# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106035");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2015-08-03 13:44:55 +0700 (Mon, 03 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Froxlor Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Froxlor.");

  script_xref(name:"URL", value:"https://froxlor.org/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

detection_patterns = make_list(
  # <title>Froxlor Server Management Panel - Installation</title>
  # <title>Froxlor Server Management Panel</title>
  # <title>Froxlor</title>
  "^\s*<title>Froxlor[^<]*</title>",

  # <p>It seems that Froxlor has not been installed yet.</p>
  ">It seems that Froxlor has not been installed yet\.<",

  # <h2>Welcome to Froxlor</h2>
  ">Welcome to Froxlor<",

  # alt="" />&nbsp;Froxlor&nbsp;-&nbsp;Login</b></td>
  # <legend>Froxlor&nbsp;-&nbsp;Login</legend>
  "Froxlor&nbsp;-&nbsp;Login",

  # <img src="templates/Froxlor/assets/img/logo.png" alt="Froxlor Server Management Panel" />
  # <img src="images/Froxlor/logo.png" alt="Froxlor Server Management Panel" />
  # <img src="templates/Sparkle/assets/img/logo.png" alt="Froxlor Server Management Panel" />
  # <img class="align-self-center my-5" src="templates/Froxlor/assets/img/logo.png" alt="Froxlor Server Management Panel"/>
  'alt="Froxlor Server Management Panel"',

  # A newer version of Froxlor has been installed but not yet set up.<br />Only the administrator can log in and finish the update.
  "A newer version of Froxlor has been installed but not yet set up\.<br */>Only the administrator can log in and finish the update\.",

  # Froxlor &copy; 2009-2013 by <a href="http://www.froxlor.org/" rel="external">the Froxlor Team</a>
  # &copy; 2009-2024 by <a href="http://www.froxlor.org/" rel="external">the Froxlor Team</a>
  # &copy; 2009-2024 by <a href="http://www.froxlor.org/" rel="external">the Froxlor Team</a><br />
  # &copy; 2009-2024 by <a href="http://www.froxlor.org/" target="_blank">the Froxlor Team</a>
  # &copy; 2009-2024 by <a href="https://www.froxlor.org/" rel="external" target="_blank">the froxlor team</a><br>
  ">the [Ff]roxlor [Tt]eam<"
);

foreach dir( make_list_unique( "/froxlor", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( port:port, item:url );

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {
      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
      found++;
    }
  }

  if( found > 1 ) {

    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"froxlor/detected", value:TRUE );
    set_kb_item( name:"froxlor/http/detected", value:TRUE );

    cpe = "cpe:/a:froxlor:froxlor";

    # While written in PHP this seems to be usually only installed on Linux/Unix systems
    os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Froxlor Detection (HTTP)", runs_key:"unixoide" );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Froxlor", version:version, install:install, cpe:cpe,
                                              concluded:concluded, concludedUrl:conclUrl ),
                 port:port );

    # nb: Usually only installed once
    exit( 0 );
  }
}

exit( 0 );
