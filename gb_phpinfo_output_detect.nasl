# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108474");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-10-19 13:33:54 +0200 (Fri, 19 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("phpinfo() output Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script tries to identify known files containing an
  output of the phpinfo() PHP function. It will also evaluate previously detected files found
  by the VT 'Web mirroring' (OID: 1.3.6.1.4.1.25623.1.0.10662).

  Note: The reporting takes place in a separate VT 'phpinfo() output Reporting' (OID: 1.3.6.1.4.1.25623.1.0.11229).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

global_var curr_phpinfo_list;
curr_phpinfo_list = make_list();

function check_and_set_phpinfo( url, host, port ) {

  local_var url, host, port, res;

  res = http_get_cache( item:url, port:port );
  if( ! res ) return;

  if( res =~ "^HTTP/1\.[01] 200" && "<title>phpinfo()</title>" >< res ) {

    curr_phpinfo_list = make_list( curr_phpinfo_list, url );

    set_kb_item( name:"php/phpinfo/detected", value:TRUE );
    set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected", value:TRUE );
    set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected_urls", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/content/phpinfo_script/plain", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/content/phpinfo_script/reporting", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

    # <h1 class="p">PHP Version 7.0.30-0+deb9u1</h1>
    vers = eregmatch( pattern:">PHP Version ([.0-9A-Za-z]+).*<", string:res );
    if( ! isnull( vers[1] ) ) {
      # nb: For later use/evaluation in gb_php_detect.nasl in the case no PHP or its version was detected from the banner
      set_kb_item( name:"php/banner/from_scripts/" + host + "/" + port + "/urls", value:url );
      replace_kb_item( name:"php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + url, value:vers[1] );
      vers = eregmatch( pattern:">PHP Version ([^<]+)<", string:res );
      if( ! isnull( vers[1] ) )
        replace_kb_item( name:"php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + url, value:vers[1] );
    }
  }
  return;
}

files  = make_list( "/phpinfo.php", "/info.php", "/test.php", "/php_info.php", "/index.php", "/i.php", "/test.php?mode=phpinfo" );

port = http_get_port( default:80 );
# nb: Don't use http_can_host_php() here as this VT is reporting PHP as well
# and http_can_host_php() could fail if no PHP was detected before...

host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  foreach file( files ) {
    url = dir + file;
    check_and_set_phpinfo( url:url, host:host, port:port );
  }
}

# nb: This is filled by webmirror.nasl, the code here makes sure that we're not reporting
# the same script twice...
kb_phpinfo_scripts = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/plain" );

if( kb_phpinfo_scripts && is_array( kb_phpinfo_scripts ) ) {
  foreach kb_phpinfo_script( kb_phpinfo_scripts ) {
    if( curr_phpinfo_list && is_array( curr_phpinfo_list ) && ! in_array( search:kb_phpinfo_script, array:curr_phpinfo_list, part_match:FALSE ) ) {
      check_and_set_phpinfo( url:kb_phpinfo_script, host:host, port:port );
    }
  }
}

exit( 0 );
