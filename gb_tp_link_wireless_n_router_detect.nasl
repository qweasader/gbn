# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811880");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-25 14:30:38 +0530 (Wed, 25 Oct 2017)");

  script_name("TP-Link Wireless Router Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of TP-Link Wireless Routers.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);
banner = http_get_remote_headers(port:port);

if(banner && banner =~ 'WWW-Authenticate: Basic realm="TP-Link.*Wireless.*Router') {
  set_kb_item(name:"TP-LINK/Wireless/Router/detected", value:TRUE);

  app = "TP-Link Wireless Router";
  cpe = "cpe:/h:tp-link:wireless-n_router";
  location = "/";
  version = "unknown";

  # TP-LINK AC1900 Wireless Dual Band Gigabit Router Archer C1900
  # TP-LINK Wireless Lite N Router WR740N/WR741ND
  # TP-LINK Wireless Dual Band Gigabit Router WDR4900
  # TP-Link Wireless N Router WR940N
  model = eregmatch(pattern:"TP-LINK.*Wireless.*Router ([A-Z0-9\-\/\s]+)", string:banner, icase:TRUE);
  if(model[1]) {
    set_kb_item(name:"TP-LINK/Wireless/Router/model", value:model[1]);
    app = model[0];
    concl = model[0];
  }

  register_product(cpe:cpe, location:location, port:port, service:"www");

  log_message(data: build_detection_report(app:app,
                                           version:version,
                                           install:location,
                                           cpe:cpe,
                                           concluded:concl),
                                           port:port);
  exit(0);
}

exit(0);
