# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107098");
  script_version("2023-06-30T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-30 16:09:17 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-05-02 14:04:20 +0200 (Tue, 02 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Emby Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8096);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Emby Server.");

  script_xref(name:"URL", value:"https://emby.media/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8096);

url = "/web/index.html";

res = http_get_cache(port: port, item: url);

if (("<title>Emby</title>" >< res || "emby-scroller" >< res) && "Energize your media" >< res &&
    ("emby-input" >< res || '"application-name" content="Emby"' >< res ||
    "mainAnimatedPages" >< res)) {
  version = "unknown";

  vers = eregmatch(pattern: "\.js\?v=([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    # data-appversion="4.7.13.0"
    vers = eregmatch(pattern: 'data-appversion="([0-9.]+)"', string: res);
    if (!isnull(vers[1])) {
      url = "/System/Info/Public";
      res = http_get_cache(port: port, item: url);
      # {"LocalAddress":"http://192.168.1.1:8096","WanAddress":"http://192.168.2.2:8096","ServerName":"mediahome","Version":"4.4.3.0","Id":"edca00eeb4004209bea345062422832d"}
      vers = eregmatch(pattern: '"Version":"([0-9.]+)"', string: res);
    }
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "emby/media_server/detected", value: TRUE);
  set_kb_item(name: "emby/media_server/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:emby:emby.releases:");
  if (!cpe)
    cpe = "cpe:/a:emby:emby.releases";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Emby Server", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
