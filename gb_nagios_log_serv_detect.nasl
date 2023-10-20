# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107058");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-12 13:26:09 +0700 (Wed, 12 Oct 2016)");

  script_name("Nagios Log Server Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Nagios Log Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-log-server/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if (!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/nagioslogserver", "/nagios", http_cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/login";
  buf = http_get_cache(port:port, item:url);

  if (buf && buf =~ "^HTTP/1\.[01] 200" && "Nagios Log Server" >< buf && "Nagios Enterprises" >< buf
      && "var LS_USER_ID" >< buf &&
      ('<div class="demosplash"></div>' >< buf || '<div class="loginsplash"></div>' >< buf)) {

    set_kb_item(name:"nagios/log_server/detected", value:TRUE);

    if ('<div class="demosplash"></div>' >< buf)
      extra = "Demo Version";

    version = "unknown";

    vers = eregmatch(string:buf, pattern:'var LS_VERSION = "([0-9.]+)"', icase:TRUE);

    # var LS_VERSION = "2.0.7";
    if (isnull(vers[1]))
      vers = eregmatch(string:buf, pattern:'ver=([0-9.]+)">');

    if (!isnull(vers[1]))
      version = vers[1];

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:nagios:log_server:");
    if (!cpe)
      cpe = 'cpe:/a:nagios:log_server';

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Nagios Log Server", version:version, install:install, cpe:cpe,
                                            concluded:vers[0], extra:extra),
                port:port);
  }
}

exit(0);
