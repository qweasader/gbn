###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Traffic Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Tim Brown <timb@openvas.org>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-03-29
# - Updated to set KB if Traffic Server is installed and grep all versions
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100796");
  script_version("2021-01-14T07:10:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-01-14 07:10:35 +0000 (Thu, 14 Jan 2021)");
  script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Traffic Server Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Apache Traffic Server.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl", "proxy_use.nasl");
  script_mandatory_keys("ATS/banner");
  script_require_ports("Services/http_proxy", 8080, 3128, 80);
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 8080, proto: "http_proxy");
banner = http_get_remote_headers(port: port);
if(!banner || ("Server: ATS/" >!< banner && "ApacheTrafficServer" >!< banner))
  exit(0);

dir = "/";
ver = "unknown";

version = eregmatch(pattern: "Server: ATS/([0-9.]+)", string: banner);
if(version[1]) {
  ver = version[1];
  set_kb_item(name: "www/" + port + "/apache_traffic_server", value: ver);
  set_kb_item(name: "apache_trafficserver/version", value: ver);
}

set_kb_item(name: "apache_trafficserver/installed", value: TRUE);

cpe = build_cpe(value: ver, exp:"^([0-9.]+)", base: "cpe:/a:apache:traffic_server:");
if(!cpe)
  cpe = "cpe:/a:apache:traffic_server";

register_product(cpe: cpe, location: dir, port: port, service: "http_proxy");

log_message(data: build_detection_report(app: "ApacheTrafficServer", version: ver, install: dir, cpe: cpe,
                                         concluded: version[0]),
            port: port);
exit(0);
