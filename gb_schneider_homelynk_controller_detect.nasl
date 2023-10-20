# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106745");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-12 11:57:47 +0200 (Wed, 12 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric homeLYnk Controller Detection");

  script_tag(name:"summary", value:"Detection of Schneider Electric homeLYnk Controller

The script sends a connection request to the server and attempts to detect Schneider Electric homeLYnk Controller
and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.schneider-electric.com/en/product-range/62143-homelynk/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8081);

res = http_get_cache(port: port, item: "/");

if ("<title>homeLYnk" >< res && "/cgi-bin/scada-vis/index.cgi" >< res) {
  version = "unknown";

  urls = make_list("/cgi-bin/scada-vis/index.cgi",
                   "/cgi-bin/scada-vis/touch.html",
                   "/cgi-bin/scada-vis/schedulers.cgi",
                   "/cgi-bin/scada-vis/trends.cgi",
                   "/cgi-bin/scada/index.cgi");

  foreach url (urls) {
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: 'config: ."version":"([0-9.]+)', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concurl = url;
      set_kb_item(name: "schneider_homelynk/version", value: version);
      break;
    }
  }

  set_kb_item(name: "schneider_homelynk/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:schneider_electric:homelynk:");
  if (!cpe)
    cpe = 'cpe:/a:schneider_electric:homelynk';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Schneider Electric homeLYnk Controller", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concurl),
              port: port);
  exit(0);
}

exit(0);
