# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809483");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-02 19:00:32 +0530 (Fri, 02 Dec 2016)");
  script_name("Apache Ranger Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Apache Ranger.

  This script sends an HTTP GET request and tries to get the version of
  Apache Ranger from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:6080);

res = http_get_cache(item:"/login.jsp", port:port);

if(res =~ "^HTTP/1\.[01] 200" && 'Ranger - Sign In</title>' >< res &&
   'Username:<' >< res && 'Password:<' >< res) {

  version = "unknown";
  install = "/";

  set_kb_item(name:"Apache/Ranger/Installed", value:TRUE);

  cpe = "cpe:/a:apache:ranger";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Apache Ranger",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}

exit(0);
