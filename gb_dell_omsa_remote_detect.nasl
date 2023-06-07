###############################################################################
# OpenVAS Vulnerability Test
#
# Dell OpenManage Server Administrator Remote Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807563");
  script_version("2021-03-04T01:43:22+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-03-04 01:43:22 +0000 (Thu, 04 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC OpenManage Server Administrator Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Dell EMC OpenManage Server Administrator.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 1311);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.dell.com/support/kbdoc/en-us/000132087/support-for-dell-emc-openmanage-server-administrator-omsa");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:1311);

foreach dir (make_list("/", "/servlet")) {
  install = dir;
  if (dir == "/")
    dir = "";

  req = http_get(item: dir + "/Login?omacmd=getlogin&page=Login&managedws=true", port: port);
  res = http_keepalive_send_recv(port: port, data: req);

  if ('application">Server Administrator' >< res && '>Login' >< res && 'dell' >< res) {
    version = "unknown";

    url =  dir + "/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern:'class="desc25">Version ([0-9.]+)' , string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "dell/openmanage_server_administrator/detected", value:TRUE);
    set_kb_item(name: "dell/openmanage_server_administrator/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:emc_openmanage_server_administrator:");
    if (!cpe)
      cpe= "cpe:/a:dell:emc_openmanage_server_administrator";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Dell EMC OpenManage Server Administrator", version: version,
                                             install: install,cpe: cpe, concluded: vers[0],
                                             concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
