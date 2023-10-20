# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103729");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-06-05 13:20:54 +0200 (Wed, 05 Jun 2013)");
  script_name("Gigaset SX762 Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SiemensGigaset-Server/banner");

  script_tag(name:"summary", value:"Detection of Gigaset SX762.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a Gigaset SX762 from the reply.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: SiemensGigaset-Server" >!< banner)
  exit(0);

url = "/UE/welcome_login.html";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Gigaset sx762" >< buf) {

  set_kb_item(name:"gigaset_sx762/installed",value:TRUE);
  cpe = "cpe:/a:siemens:gigaset:sx762";

  register_product(cpe:cpe, location:port + "/tcp", port:port, service:"www");

  log_message(data:"The remote Host is a Siemens Gigaset sx762 device.\nCPE: " + cpe + "\n", port:port);
  exit(0);
}

exit(0);
