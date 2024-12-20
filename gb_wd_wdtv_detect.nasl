# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141283");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-09 13:22:30 +0200 (Mon, 09 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Western Digital WD TV Detection");

  script_tag(name:"summary", value:"Detection of Western Digital WD TV.

The script sends a connection request to the server and attempts to detect Western Digital WD TV and to extract
its firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8080, 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.wdc.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/cgi-bin/getServerValue.cgi?id=2");

# { "Storage": [ { "LocalStroge": "Local storage", "Volume": "WDTVLiveHub\n", "Used": "692.03GB", "Total": "930.44GB", "Status": "Good" } ] }
# There might be some other devices with different responses
if ("WDTVLiveHub" >< res) {
  version = "unknown";

  # Currently hardcoded, could be dynamic set with further info on different devices
  model = "Live Hub";

  url = '/cgi-bin/getServerValue.cgi?id=7';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: '"VISION": "([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "wd_wdtv/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:western_digital:wdtv_live_hub:");
  if (!cpe)
    cpe = 'cpe:/a:western_digital:wdtv_live_hub';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Western Digital WD TV " + model, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
