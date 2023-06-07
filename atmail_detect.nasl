###############################################################################
# OpenVAS Vulnerability Test
#
# Atmail Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100148");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-04-17 18:35:24 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Atmail Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Atmail.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

files = make_list("/index.php", "/index.php/admin");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/mail", "/webmail", "/atmail", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file ( files ) {
    url = dir + file;
    buf = http_get_cache( item:url, port:port );

    if (egrep(pattern: "Powered by Atmail", string: buf, icase: TRUE) ||
        egrep(pattern: "<title>Login to Atmail</title>", string: buf) ||
        egrep(pattern: "For more information on the WebMail service.*Atmail PHP [0-9.]+", string: buf) ||
        "Use an enhanced accessible version of Atmail" >< buf) {
      vers = "unknown";

      version = eregmatch(string: buf, pattern: "Powered by Atmail ([0-9.]+)",icase:TRUE);
      if (!isnull(version[1])) {
        vers = version[1];
        set_kb_item(name: "Atmail/version", value: vers);
      }
      else {
        version = eregmatch(string: buf,
                            pattern: "For more information on the WebMail service, please contact.*Atmail PHP ([0-9.]+)",
                            icase:TRUE);

        if (!isnull(version[1])) {
          vers = version[1];
          set_kb_item(name: "Atmail/version", value: vers);
        }
        else {
          version = eregmatch(string: buf, pattern: "login\?([0-9.]+)");
          if (!isnull(version[1])) {
            vers = version[1];
            set_kb_item(name: "Atmail/version", value: vers);
          }
          else {
            version = eregmatch(string: buf, pattern: "favicon-admin.ico\?([0-9.]+)");
            if (!isnull(version[1])) {
              vers = version[1];
              set_kb_item(name: "Atmail/version", value: vers);
            }
          }
        }
      }

      set_kb_item(name:"Atmail/installed", value:TRUE);

      cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:atmail:atmail:");
      if(isnull(cpe))
        cpe = 'cpe:/a:atmail:atmail';

      register_product(cpe:cpe, location:install, port:port, service:"www");

      log_message(data: build_detection_report(app: "Atmail", version: vers, install: install, cpe: cpe,
                                               concluded: version[0]),
                  port:port);

      exit(0);
    }
  }
}

exit(0);