###############################################################################
# OpenVAS Vulnerability Test
#
# SugarCRM Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106122");
  script_version("2020-11-25T06:50:09+0000");
  script_tag(name:"last_modification", value:"2020-11-25 06:50:09 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-07-08 14:44:45 +0700 (Fri, 08 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SugarCRM Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of SugarCRM.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_suitecrm_detect.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sugarcrm.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

# Don't detect SuiteCRM as SugarCRM on the same port
if (get_kb_item("salesagility/suitecrm/" + port + "/detected"))
  exit(0);

foreach dir (make_list_unique("/sugarcrm", "/SugarCRM", "/sugar", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php?action=Login&module=Users&login_module=Home&login_action=index";
  res = http_get_cache(port: port, item: url);
  # for version 7 and later
  res2 = http_get_cache(port: port, item: dir + "/");

  if ("alt='Powered By SugarCRM'>" >< res || "Set-Cookie: sugar_user_them" >< res ||
      (res2 =~ "<title>(.*)?SugarCRM</title>" && "var parentIsSugar" >< res2)) {
    version = "unknown";
    edition = "";

    url = dir + '/sugar_version.json';
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);
    ver = eregmatch(pattern: '"sugar_version":( )?"([0-9.]+)",', string: res);
    if (!isnull(ver[2])) {
      version = ver[2];
      concUrl = url;
    }

    ed = eregmatch(pattern: '"sugar_flavor":( )?"([^"]+)",', string: res);
    if (!isnull(ed[2])) {
      edition = ed[2];
      set_kb_item(name: "sugarcrm/edition", value: edition);
    }

    set_kb_item(name: "sugarcrm/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sugarcrm:sugarcrm:");
    if (!cpe)
      cpe = "cpe:/a:sugarcrm:sugarcrm";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SugarCRM " + edition, version: version, install: install,
                                             cpe: cpe, concluded: ver[0], concludedUrl: concUrl),
                port: port);
  }
}

exit(0);
