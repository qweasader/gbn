###############################################################################
# OpenVAS Vulnerability Test
#
# Filr Web Administration Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105825");
  script_version("2020-12-16T08:51:38+0000");
  script_tag(name:"last_modification", value:"2020-12-16 08:51:38 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2016-07-25 16:16:12 +0200 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus (Novell) Filr Administration Interface Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Micro Focus (Novell) Filr Administration Interface.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9443);

url = "/login";
res = http_get_cache(port: port, item: url);

if (res =~ "<title>(Novell )?Filr Appliance</title>" && ">Administration<" >< res) {
  version = "unknown";

  set_kb_item(name: "microfocus/filr/detected", value: TRUE);
  set_kb_item(name: "microfocus/filr/admin_http/port", value: port);
  set_kb_item(name: "microfocus/filr/admin_http/" + port + "/version", value: version);
}

exit(0);
