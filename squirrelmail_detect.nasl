# OpenVAS Vulnerability Test
# Description: SquirrelMail Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12647");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SquirrelMail Detection");

  script_tag(name:"summary", value:"Detection of SquirrelMail.

The script sends a connection request to the server and attempts to detect SquirrelMail and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.squirrelmail.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port:port)) exit(0);

foreach dir (make_list_unique("/squirrelmail", "/squirrel", "/webmail", "/mail", "/sm", http_cgi_dirs( port:port ))) {
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/src/login.php";
  res = http_get_cache( item:url, port:port );

  if (res =~ "<title>Squirrel[mM]ail - Login</title>" || "squirrelmail_loginpage_onload" >< res) {
    version = "unknown";

    # Search in a couple of different pages.
    files = make_array("/src/login.php", "SquirrelMail [vV]ersion ([0-9.]+)",
                       "/src/compose.php", "SquirrelMail [vV]ersion ([0-9.]+)<BR",
                       "/src/configtest.php", "SquirrelMail version:</td><td><b>([0-9.]+)",
                       "/doc/ChangeLog", "Version ([0-9.]+) - [0-9]",
                       "/doc/ReleaseNotes", "Release Notes: SquirrelMail ([0-9.]+)");

    foreach file (keys(files)) {
      res = http_get_cache(port: port, item: dir + file);

      vers = eregmatch(pattern: files[file], string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "squirrelmail/version", value: version);
        concurl = dir + file;
        break;
      }
    }

    set_kb_item(name: "squirrelmail/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:squirrelmail:squirrelmail:");
    if (!cpe)
      cpe = 'cpe:/a:squirrelmail:squirrelmail';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SquirrelMail", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concurl),
                port: port);
  }
}

exit(0);

