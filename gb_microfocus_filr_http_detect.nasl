# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105826");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-25 16:16:12 +0200 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus (Novell) Filr Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Micro Focus (Novell) Filr.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8443);

url = "/filr/#/login";
res = http_get_cache(port: port, item: url);
if ("<title>Micro Focus Filr</title>" >!< res) {
  url = "/ssf/a/do?p_name=ss_forum&p_action=1&action=__login";
  res = http_get_cache(port: port, item: url);
}

if (res =~ "<title>(Novell|Micro Focus) Filr</title>") {
  version = "unknown";

  set_kb_item(name: "microfocus/filr/detected", value: TRUE);
  set_kb_item(name: "microfocus/filr/http/port", value: port);

  url = "/rest/public";
  headers = make_array("Content-Type", "application/json; charset=utf-8");

  req = http_get_req(port: port, url: url, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  # "productVersion":"4.2.2.2"
  vers = eregmatch(pattern: '"productVersion":"([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "microfocus/filr/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "microfocus/filr/http/" + port + "/concludedUrl",
                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "microfocus/filr/http/" + port + "/version", value: version);
}

exit(0);
