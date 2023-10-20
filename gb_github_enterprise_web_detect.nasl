# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140195");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-17 16:36:11 +0100 (Fri, 17 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("GitHub Enterprise WebGUI / Management Console Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the GitHub Enterprise WebGUI or
  Management Console.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:8443 );

foreach dir( make_list( "/login", "/setup/unlock" ) ) {

  detected = FALSE;
  version  = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:dir, url_only:TRUE );

  buf = http_get_cache( item:dir, port:port );
  if( ! buf || ( buf !~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 402" ) ) continue; # nb: 402 for the case where the license expired.

  if( buf =~ "<title>(Setup )?GitHub Enterprise( preflight check)?</title>" ||
      "Please enter your password to unlock the GitHub Enterprise management" >< buf ||
      "GitHub Enterprise requires one of the following" >< buf ||
      'enterprise.github.com/support">contact support' >< buf ) {

    app_name = "GitHub Enterprise Management Console";
    install  = "/setup";
    detected = TRUE;
    set_kb_item( name:"github/enterprise/management_console/detected", value:TRUE );

  } else if( ( buf =~ "<title>GitHub . Enterprise</title>" && # nb: The dot is expected here as the title contains an UTF-8 char which we can't use in VTs yet...
               '<meta name="description" content="GitHub is where people build software.' >< buf ) ||
             buf =~ '<img alt="GitHub Enterprise logo" src=".*/images/modules/enterprise/gh-enterprise-logo.svg"' ||
             ( "Sorry, your GitHub Enterprise license expired" >< buf && "<h1>License Expired</h1>" >< buf ) ) {

    # <li><a href="https://help.github.com/enterprise/2.11">Help</a></li>
    # <li class="mr-3"><a href="https://help.github.com/enterprise/2.13" class="link-gray">Help</a></li>
    # <li class="mr-3"><a href="https://help.github.com/enterprise/2.14" class="link-gray">Help</a></li>
    #
    # nb: Only the major release seems to be included here.
    vers = eregmatch( pattern:'<a href="https://help.github.com/enterprise/([0-9.]+)"', string:buf );
    if( vers[1] )
      version = vers[1];

    app_name = "GitHub Enterprise WebGUI";
    install  = "/";
    detected = TRUE;
    set_kb_item( name:"github/enterprise/webgui/detected", value:TRUE );
  }

  if( detected ) {
    register_and_report_cpe( app:app_name, ver:version, concluded:vers[0], conclUrl:conclUrl, base:"cpe:/a:github:github_enterprise:", expr:"^([0-9.]+)", regPort:port, regService:"www", insloc:install );
  }
}

exit( 0 );
