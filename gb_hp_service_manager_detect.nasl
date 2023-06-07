###############################################################################
# OpenVAS Vulnerability Test
#
# HP / Micro Focus Service Manager Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.106125");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-07-11 12:33:22 +0700 (Mon, 11 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP / Micro Focus Service Manager Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of HP / Micro Focus Service Manager

  The script sends a connection request to the server and attempts to detect the presence of HP / Micro Focus
  Service Manager and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www8.hp.com/us/en/software-solutions/service-desk/index.html");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/sm", "/sm7", "/sc", "/hpsm", "/webtier", "/sm-webtier", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.do";
  res = http_get_cache(port: port, item: url);
  if (res =~ 'Location: (https?://[^/]+)?/' + dir + '/ess\\.do\r\n') {
    url = dir + "/ess.do";
    res = http_get_cache(port: port, item: url);
  }

  if ("HPLogoSolidBlue.ico" >< res && 'id="old\\.password"[ ]+name="old\\.password"/>' >< res) {
    version = "unknown";

    ver = eregmatch(pattern: '<script type="text/javascript" src="([/a-z]+)([0-9.]+).*login\\.js"></script>',
                    string: res);
    if (!isnull(ver[2]))
      version = ver[2];
    else {
      ver = eregmatch(pattern: 'href="([/a-z]+)([0-9.]+)/login\\.css">', string: res);
      if (!isnull(ver[2]))
        version = ver[2];
      else {
        ver = eregmatch(pattern: "\.ico\?v=([0-9.]+)", string: res);
        if (!isnull(ver[1]))
          version = ver[1];
      }
    }

    set_kb_item(name: "hp_service_manager/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:service_manager:");
    if (isnull(cpe))
      cpe = "cpe:/a:hp:service_manager";

    register_product(cpe: cpe, location: install, port: port);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:microfocus:service_manager:");
    if (isnull(cpe))
      cpe = "cpe:/a:microfocus:service_manager";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "HP/MicroFocus Service Manager", version: version,
                                             install: install, cpe: cpe, concluded: ver[0]),
                port: port);

    exit(0);
  }
}

exit(0);
