# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106844");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-02 13:17:40 +0700 (Fri, 02 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Riverbed SteelHead Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Riverbed SteelHead.

The script sends a connection request to the server and attempts to detect Riverbed SteelHead
devices and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.riverbed.com/products/steelhead/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

source = "http";

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/login");

if ('product-name">SteelHead' >< res && 'id="rvbdLoginLogoContainer">' >< res) {
  version = "unknown";
  report_app = "Riverbed SteelHead";

  url = '/api/common/1.0/info';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # { "device_name": "amnesiac", "model": "VCX", "serial": "XXXXXXXXXXX", "sw_version": "9.6.0a" }
  mod = eregmatch(pattern: '"model": "([^"]+)"', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    report_app += ' ' + model;
    set_kb_item(name: "riverbed/steelhead/model", value: model);
  }

  vers = eregmatch(pattern: '"sw_version": "([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "riverbed/steelhead/version", value: version);
  }

  set_kb_item(name: "riverbed/steelhead/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:riverbed:steelhead:");
  if (!cpe)
    cpe = 'cpe:/a:riverbed:steelhead';

  os_register_and_report(os: "Riverbed Optimization System (RiOS)", cpe: "cpe:/o:riverbed:riverbed_optimization_system", desc: "Riverbed SteelHead Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: report_app, version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: url),
              port: port);
  exit(0);
}

exit(0);
