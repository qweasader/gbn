# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809058");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Flexense SyncBreeze Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Flexense SyncBreeze.

  The script sends a connection request to the server and attempts to detect Flexense SyncBreeze and to extract its
  version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

res = http_get_cache(item:"/login", port:port);

if(">Sync Breeze Enterprise" >< res && ">User Name" >< res && ">Password" >< res) {

  version = "unknown";

  syncVer = eregmatch(pattern:">Sync Breeze Enterprise v([0-9.]+)", string:res);
  if (syncVer[1])
    version = syncVer[1];

  set_kb_item(name:"flexsense_syncbreeze/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:flexense:syncbreeze:");
  if(!cpe)
    cpe = "cpe:/a:flexense:syncbreeze";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"Flexsense Sync Breeze Enterprise", version:version,
                                          install:"/", cpe:cpe, concluded:syncVer[0]),
              port:port);
  exit(0);
}

exit(0);
