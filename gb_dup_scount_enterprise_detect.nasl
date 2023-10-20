# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809064");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-13 16:11:25 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dup Scout Enterprise Detection (HTTP)");

  script_tag(name:"summary", value:"Detects the installed version of
  Dup Scout Enterprise.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);
res = http_get_cache(item:"/login", port:port);

if(">Dup Scout Enterprise" >< res &&
   ">User Name" >< res && ">Password" >< res) {

  version = "unknown";

  vers = eregmatch(pattern:">Dup Scout Enterprise v([0-9.]+)", string:res);
  if(vers[1])
    version = vers[1];

  set_kb_item(name:"Dup/Scout/Enterprise/installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:dup:dup_scout_enterprise:");
  if(!cpe)
    cpe = "cpe:/a:dup:dup_scout_enterprise";

  register_product(cpe:cpe, location:"/", port:port, service:"www");
  log_message(data: build_detection_report(app: "Dup Scout Enterprise",
                                           version:version,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:vers[0]),
                                           port:port);
}

exit(0);
