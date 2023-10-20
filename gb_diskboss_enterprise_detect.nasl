# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140094");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-06 16:11:25 +0530 (Tue, 06 Dec 2016)");
  script_name("DiskBoss Enterprise Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  DiskBoss Enterprise.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

dbossPort = http_get_port(default:8080);
res = http_get_cache(item:"/login", port:dbossPort);

if(">DiskBoss Enterprise" >< res &&
   ">User Name" >< res && ">Password" >< res)
{

  dbossVer = "unknown";
  install  = "/";

  vers = eregmatch(pattern:">DiskBoss Enterprise v([0-9.]+)", string:res);
  if(vers[1]) dbossVer = vers[1];

  set_kb_item(name:"Disk/Boss/Enterprise/installed", value:TRUE);

  cpe = build_cpe(value:dbossVer, exp:"([0-9.]+)", base:"cpe:/a:dboss:diskboss_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:dboss:diskboss_enterprise";

  register_product(cpe:cpe, location:install, port:dbossPort, service:"www");
  log_message(data:build_detection_report(app:"DiskBoss Enterprise",
                                          version:dbossVer,
                                          install:install,
                                          cpe:cpe,
                                          concluded:vers[0]),
                                          port:dbossPort);
}

exit(0);
