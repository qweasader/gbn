# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103830");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-11-13 18:05:10 +0100 (Wed, 13 Nov 2013)");
  script_name("Webuzo Detection (HTTP)");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2002, 2004);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:2004);
if(!http_can_host_php(port:port))
  exit(0);

url = "/index.php?act=login";
buf = http_get_cache(item:url, port:port);
if("<title>Login" >< buf && "Powered By Webuzo" >< buf && "SOFTCookies" >< buf) {

  set_kb_item(name:"webuzo/installed", value:TRUE);
  vers = 'unknown';

  version = eregmatch(pattern:"Powered By Webuzo ([0-9.]+)", string:buf);
  if(!isnull(version[1]))
    vers = version[1];

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:softaculous:webuzo:");
  if(!cpe)
    cpe = "cpe:/a:softaculous:webuzo";

  register_product(cpe:cpe, location:url, port:port, service:"www");

  log_message(data:build_detection_report(app:"Webuzo", version:vers, install:url, cpe:cpe, concluded:version[0]),
              port:port);

}

exit(0);
