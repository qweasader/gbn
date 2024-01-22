# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141472");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-09-12 16:07:21 +0700 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MedDream PACS Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of MedDream PACS Server.

  The script sends a connection request to the server and attempts to detect MedDream PACS Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.softneta.com/products/meddream-pacs-server/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/pacs/login.php");

if ("Not authorized to access this URL" >< res && "loginSplash" >< res) {
  version = "unknown";

  set_kb_item(name: "meddream_pacs/detected", value: TRUE);

  cpe = "cpe:/a:softneta:meddreams_pacs";

  register_product(cpe: cpe, location: "/pacs", port: port, service: "www");

  log_message(data: build_detection_report(app: "MedDream PACS", version: version, install: "/pacs", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
