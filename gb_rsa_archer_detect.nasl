###############################################################################
# OpenVAS Vulnerability Test
#
# RSA Archer Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.106918");
  script_version("2021-02-02T02:20:48+0000");
  script_tag(name:"last_modification", value:"2021-02-02 02:20:48 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-07-03 15:23:44 +0700 (Mon, 03 Jul 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RSA Archer Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of RSA Archer.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rsa.com/en-us/products/governance-risk-and-compliance/archer-platform");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/RSAarcher", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/Default.aspx");

  if ("Subscriber Log On" >< res && 'class="Logo">RSA Archer' >< res && "ArcherTech.UI.UserLogin" >< res) {
    version = "unknown";

    vers = eregmatch(pattern: "ArcherVersion=([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "rsa_archer/version", value: version);
    }

    set_kb_item(name: "rsa_archer/installed", value: TRUE);

    cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:rsa:rsa_archer:");
    if (!cpe1)
      cpe1 = "cpe:/a:rsa:rsa_archer";

    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:emc:rsa_archer_grc:");
    if (!cpe2)
      cpe2 = "cpe:/a:emc:rsa_archer_grc";

    register_product(cpe: cpe1, location: install, port: port, service: "www");
    register_product(cpe: cpe2, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "RSA Archer", version: version, install: install, cpe: cpe1,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
