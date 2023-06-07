###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds Orion VoIP and Network Quality Manager Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105963");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-03-06 15:15:25 +0700 (Fri, 06 Mar 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Orion VoIP and Network Quality Manager Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8787);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks for the presence of SolarWinds Orion VoIP and Network Quality Manager.");
  script_xref(name:"URL", value:"http://www.solarwinds.com/products/orion/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8787);

if (!http_can_host_asp(port:port))
  exit(0);

dir = "/Orion";
url = string(dir, "/Login.aspx");
buf = http_get_cache(item:url, port:port);
if (!buf)
  exit(0);

if ("SolarWinds Platform" >< buf || "SolarWinds Orion" >< buf || "Orion Platform" >< buf) {
  vnqm = eregmatch(string:buf, pattern: "VNQM ([0-9.]+)", icase:TRUE);
  if (!isnull(vnqm)) {
    vers = string("unknown");
    if (!isnull(vnqm[1])) {
      vers=chomp(vnqm[1]);
    }

    set_kb_item(name: string("www/", port, "/orion_vnqm"), value: vers);
    set_kb_item(name: "orion_vnqm/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp:"^([0-9.]+)", base: "cpe:/a:solarwinds:voip_and_network_quality_manager:");
    if (isnull(cpe))
      cpe = 'cpe:/a:solarwinds:voip_and_network_quality_manager';

    register_product(cpe:cpe, location:dir, port:port, service:"www");

    log_message(data: build_detection_report(app:"SolarWinds VoIP and Network Quality Manager", version: vers,
                                             install: dir, cpe: cpe,
                                             concluded: vnqm[0]), port:port);
  }
}

exit(0);
