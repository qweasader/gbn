# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106106");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa EDS-40x/50x Detection");

  script_tag(name:"summary", value:"Detection of Moxa EDS-40x and 50x Series Ethernet Switches

The script sends a connection request to the server and attempts to detect Moxa EDS-405A/EDS-408A Ethernet
Switches");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.moxa.com/");


  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 81);
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

req = http_get(port: port, item: "/auth/led_auth.asp");
res = http_keepalive_send_recv(port: port, data: req);

if (res && ("MasterLEDName" >< res) && egrep(pattern: 'EDS-(4|5)0.A', string: res)) {
  mod = eregmatch(pattern: 'ModelName" value="(EDS-(4|5)0.A)', string: res);
  if (isnull(mod[1]))
    exit(0);
  else
    model = mod[1];

  version = "unknown";
  build = "unknown";
  ver = eregmatch(pattern: 'FirmVersion" value="V([0-9.]+)( build ([0-9]+))?', string: res);
  if (!isnull(ver[1]))
    version = ver[1];
  if (!isnull(ver[3]))
    build = ver[3];

  set_kb_item(name: "moxa_eds/detected", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: string("www/", port, "/moxa/version"), value: version);
  if (build != "unknown")
    set_kb_item(name: string("www/", port, "/moxa/build"), value: build);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:moxa:" + tolower(model) + ":");
  if (isnull(cpe))
    cpe = 'cpe:/a:moxa:' + tolower(model);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Moxa " + model, version: version, install: "/",
                                           cpe: cpe, concluded: ver[0]),
              port: port);
}

exit(0);
