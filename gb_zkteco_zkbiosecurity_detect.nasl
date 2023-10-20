# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809334");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-06 14:17:14 +0530 (Thu, 06 Oct 2016)");
  script_name("ZKTeco ZKBioSecurity Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  ZKTeco ZKBioSecurity.

  This script sends an HTTP GET request and tries to ensure the presence of
  ZKTeco ZKBioSecurity.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

zktPort = http_get_port(default:8088);

res = http_get_cache(item:"/", port:zktPort);

if('<title>ZKBioSecurity</title>' >< res && 'password' >< res)
{
    install = "/";
    version = "unknown";

    set_kb_item(name:"ZKTeco/ZKBioSecurity/Installed", value:TRUE);

    ## Created new cpe
    cpe = "cpe:/a:zkteco:zkbiosecurity";

    register_product(cpe:cpe, location:install, port:zktPort, service:"www");

    log_message(data:build_detection_report(app:"ZKteco ZKBioSecurity",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:zktPort);
  }

exit(0);
