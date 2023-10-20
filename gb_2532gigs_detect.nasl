# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800681");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("2532|Gigs Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of 2532-Gigs.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

gigsPort = http_get_port(default:80);

if( !http_can_host_php( port:gigsPort ) ) exit( 0 );

foreach dir (make_list_unique("/2532Gigs", "/Gigs", "/bands", http_cgi_dirs(port:gigsPort)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:dir + "/index.php", port:gigsPort);

  if("Powered by 2532|Gigs" >< rcvRes)
  {
    gigsVer = eregmatch(pattern:"2532\|Gigs v([0-9]+\.[0-9]\.[0-9])",
                        string:rcvRes);

    version = "unknown";

    if(gigsVer[1] != NULL) version = gigsVer[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + gigsPort + "/2532|Gigs", value:tmp_version);
    set_kb_item(name:"2532_gigs/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:2532gigs:2532gigs:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:2532gigs:2532gigs';

    register_product( cpe:cpe, location:install, port:gigsPort, service:"www" );

    log_message( data: build_detection_report( app:"2532Gigs",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: gigsVer[0]),
                                               port:gigsPort);

  }
}
