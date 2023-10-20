# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107044");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-07 13:18:59 +0200 (Wed, 07 Sep 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Loxone Miniserver Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Loxone Miniserver devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
res = http_get_cache(port: port, item: "/");

if (banner =~ "Server\s*:\s*Loxone" || (("title>Loxone</title>" >< res || "CloudDNS" >< res) &&
    (res =~ "frame-src 'self' [^.]+\.loxone\.com" || "loxoneControl.js" >< res || "loxCSSCommon.css" >< res))) {
  version = "unknown";

  set_kb_item(name: "loxone/miniserver/detected", value: TRUE);
  set_kb_item(name: "loxone/miniserver/http/detected", value: TRUE);
  set_kb_item(name: "loxone/miniserver/http/port", value: port);

  url = "/jdev/cfg/apiKey";
  headers = make_array("X-Requested-With", "XMLHttpRequest");

  req = http_get_req(port: port, url: url, add_headers: headers);
  res2 = http_keepalive_send_recv(port: port, data: req);

  # {"LL": { "control": "dev/cfg/apiKey", "value": "{'snr': '51:5F:93:12:AC:A6', 'version':'11.1.9.14', 'key':'36453144423132454133314343323731373531324436354233434546374741364330324231314132'}", "Code": "200"}}
  vers = eregmatch(pattern: "'version':'([0-9.]+)'", string: res2);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "loxone/miniserver/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "loxone/miniserver/http/" + port + "/concludedUrl",
                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  } else {
    # Server: Loxone 6.2.12.4
    # Server: Loxone 3.5.7.3
    vers = eregmatch(pattern: "Server\s*:\s*Loxone ([0-9.]+)", string: res, icase: TRUE);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "loxone/miniserver/http/" + port + "/concluded", value: vers[0]);
    }
  }

  set_kb_item(name: "loxone/miniserver/http/" + port + "/version", value: version);
}

exit(0);
