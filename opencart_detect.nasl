###############################################################################
# OpenVAS Vulnerability Test
#
# OpenCart Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100178");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenCart Detection");

  script_tag(name:"summary", value:"Detects the installed version of OpenCart, free online store system.

  The script sends a request to access the 'admin/index.php' and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

ocPort = http_get_port(default:80);
if(!http_can_host_php(port:ocPort))exit(0);

foreach dir( make_list_unique( "/shop", "/store", "/opencart", "/upload", http_cgi_dirs( port:ocPort ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:ocPort );
  if( ! buf ) continue;

  if(
    (egrep(pattern: "Powered By <a [^>]+>OpenCart", string: buf, icase: TRUE) ||
     egrep(pattern: "<title>.* \(Powered By OpenCart\)</title>", string: buf, icase: TRUE)) &&
     egrep(pattern: 'Set-Cookie: language=', string: buf, icase: TRUE) )
  {
    vers = "unknown";

    sndReq = http_get(item: dir + "/admin/index.php", port: ocPort);
    rcvRes = http_keepalive_send_recv(port:ocPort, data:sndReq);

    cartVer = eregmatch(pattern:">Version ([0-9.]+)<", string:rcvRes);
    if(!isnull(cartVer[1]))
      vers = cartVer[1];
    else {
      url = dir + "/CHANGELOG.md";
      res = http_get_cache(port: ocPort, item: url);

      # ## [v3.0.1.2] (Release date: 07.07.2017)
      cartVer = eregmatch(pattern: "\#\# .v([0-9.]+)", string: res);
      if (!isnull(cartVer[1])) {
        vers = cartVer[1];
        concUrl = url;
      }
    }

    set_kb_item(name:"OpenCart/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:opencart:opencart:");
    if(!cpe)
      cpe = 'cpe:/a:opencart:opencart';

    register_product(cpe:cpe, location:install, port:ocPort, service:"www");

    log_message(data: build_detection_report(app:"OpenCart",
                                           version: vers,
                                           install: install,
                                           cpe: cpe,
                                           concluded: vers, concludedUrl: concUrl),
                port: ocPort);
 }
}

exit( 0 );
