# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144114");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-06-16 08:27:51 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Geneko Router Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Geneko routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

# nb: Don't use http_get_cache() / http_keepalive_send_recv(), both currently won't return the HTTP body.
# This is due to some devices reporting a "Content-Length: 0" but including data in the body which is
# skipped by both functions.
#res = http_get_cache(port: port, item: "/");
req = http_get(port: port, item: "/");
res = http_send_recv(port: port, data: req);

if ('usemap="#zaglmap"' >< res && "ruter.css" >< res && ("Geneko" >< res || "lib/gwr.js" >< res)) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "geneko/router/detected", value: TRUE);
  set_kb_item(name: "geneko/router/http/detected", value: TRUE);
  set_kb_item(name: "geneko/router/http/port", value: port);
  set_kb_item(name: "geneko/router/http/" + port + "/version", value: version);
  set_kb_item(name: "geneko/router/http/" + port + "/model", value: model);
}

exit(0);
