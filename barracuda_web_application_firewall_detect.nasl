# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100419");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Web Application Firewall Detection");

  script_tag(name:"summary", value:"Detection of Barracuda Web Application Firewall

The script sends a connection request to the server and attempts to detect the presence of Barracuda Web
Application Firewall and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.barracuda.com/products/webapplicationfirewall");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/cgi-mod/index.cgi";
buf = http_get_cache(port: port, item: url);

if (egrep(pattern: "<title>Barracuda Web Application Firewall", string: buf, icase: TRUE)) {
  version = 'unknown';

  vers = eregmatch(string: buf, pattern: "barracuda.css\?v=([0-9.]+)",icase:TRUE);
  if (!isnull(vers[1]))
    version = chomp(vers[1]);

  set_kb_item(name: "barracuda_waf/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "barracuda_waf/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:barracuda:web_application_firewall:");
  if (!cpe)
    cpe = "cpe:/a:barracuda:web_application_firewall";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Barracuda Web Application Firewall",
                                           version: version, install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
