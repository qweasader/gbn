###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix NetScaler Detection (HTTP)
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2008 nnposter
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80024");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Citrix NetScaler Detection (HTTP)");

  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 nnposter");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.citrix.com/networking/");

  script_tag(name:"summary", value:"Detection of Citrix Netscaler Web UI.

The script sends a connection request to the server and attempts to detect Citrix Netscaler and to extract its
version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

foreach url(make_list("/vpn/tmindex.html", "/vpn/index.html", "/", "/index.html")) {

  res = http_get_cache(item: url, port: port);
  if(!res)
    continue;

  # <TITLE>Citrix Access Gateway - Enterprise Edition</TITLE>
  # <TITLE>Citrix Access Gateway</TITLE>
  if ((res !~ "<title>Citrix Login</title>" || res !~ 'action="(/login/do_login|/ws/login\\.pl)"') &&
      res !~ "<title>netscaler gateway</title>" &&
      res !~ "<title>citrix access gateway(\s*-\s*.* edition)?</title>")
    continue;

  set_kb_item(name: "citrix_netscaler/detected", value: TRUE);
  set_kb_item(name: "citrix_netscaler/http/detected", value: TRUE);
  set_kb_item(name: "citrix_netscaler/http/port", value: port);
  set_kb_item(name: "citrix_netscaler/http/" + port + "/detectUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  version = "unknown";

  url2 = "/epa/epa.html";
  req = http_get(item: url2, port: port);
  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  # var nsversion="12,0,41,23";
  vers = eregmatch(pattern: 'var nsversion="([^;]+)";', string: buf);

  if (isnull(vers[1])) {
    url2 = "/api/NSConfig.wsdl";
    req = http_get(item: url2, port: port);
    buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
    # <!--  #NS7.0 Build 56  -->
    vers = eregmatch(pattern: "#NS([0-9.]+ Build [[0-9]+)", string: buf);
  }

  if (!isnull(vers[1])) {
    version = str_replace(string: vers[1], find: ",", replace: ".");
    version = str_replace(string: version, find: " Build ", replace: ".");
    set_kb_item(name: "citrix_netscaler/http/" + port + "/version", value: version);
    set_kb_item(name: "citrix_netscaler/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "citrix_netscaler/http/" + port + "/concUrl", value: http_report_vuln_url(port: port, url: url2, url_only: TRUE));
  }

  exit(0);
}

exit(0);
