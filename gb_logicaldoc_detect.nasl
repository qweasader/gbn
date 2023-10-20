# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140769");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-13 10:43:53 +0700 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LogicalDOC Detection");

  script_tag(name:"summary", value:"Detection of LogicalDOC.

The script sends a connection request to the server and attempts to detect LogicalDOC.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.logicaldoc.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/logicaldoc", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  names = make_list("frontend", "login");
  foreach name (names) {
    res = http_get_cache(port: port, item: dir + "/" + name + "/" + name + ".nocache.js");
    ub = eregmatch(pattern: ",Ub='([^']+)", string: res);
    if (isnull(ub[1]))
      continue;
    else {
      found_name = name;
      break;
    }
  }

  if (isnull(ub[1]))
    continue;

  url = dir + "/" + found_name + "/" + ub[1] + ".cache.html";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("logicaldoc" >< res) {
    # the version is retrieved via POST call to /login/info with a highly dynamic input computed in javascript
    # which we can't handle
    version = "unknown";

    set_kb_item(name: "logicalDOC/installed", value: TRUE);

    cpe = 'cpe:/a:logicaldoc:logicaldoc';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "LogicalDOC", version: version, install: install, cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);
