# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147836");
  script_version("2022-03-22T09:02:09+0000");
  script_tag(name:"last_modification", value:"2022-03-22 09:02:09 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 08:24:49 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Papoo CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Papoo CMS.");

  script_xref(name:"URL", value:"https://www.papoo.de/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/cms", "/papoo", "/pp", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if ('name="Creator" content="Papoo"' >< res || 'name="Papoo-version"' >< res ||
      'alt="Powered by Papoo' >< res) {
    version = "unknown";

    # <meta name="Papoo-version" content="19.06 Rev. 1584 - Papoo Light" />
    vers = eregmatch(pattern: '"Papoo-version"\\s+content="([0-9.]+)[^"]*"', string: res);
    if (isnull(vers[1])) {
      # Papoo Version 21.02 Rev. 04f1ca6 - Papoo Light
      vers = eregmatch(pattern: "Papoo Version ([0-9.]+)", string: res);
    }

    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "papoo_cms/detected", value: TRUE);
    set_kb_item(name: "papoo_cms/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:papoo:papoo:");
    if (!cpe)
      cpe = "cpe:/a:papoo:papoo";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Papoo CMS", version: version, install: install,
                                             cpe: cpe, concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
