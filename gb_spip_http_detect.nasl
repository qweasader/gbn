# Copyright (C) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103776");
  script_version("2023-03-02T10:19:53+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-08-29 11:47:51 +0200 (Thu, 29 Aug 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SPIP Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of SPIP.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.spip.net");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/spip", http_cgi_dirs( port:port ) ) ) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/spip.php";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if ("Composed-By: SPIP" >< buf) {
    vers = 'unknown';

    version = eregmatch(pattern:"Composed-By: SPIP ([0-9a-z.]+)", string:buf);
    if (isnull(version[1]))
      version = eregmatch(pattern:'meta name="generator" content="SPIP ([0-9a-z]+)', string:buf);

    if(!isnull(version[1]))
      vers = version[1];

    set_kb_item(name:"spip/detected",value:TRUE);
    set_kb_item(name:"spip/http/detected",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9a-z.]+)", base:"cpe:/a:spip:spip:");
    if (!cpe)
      cpe = "cpe:/a:spip:spip";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data: build_detection_report(app:"SPIP", version:vers, install:install, cpe:cpe,
                                             concluded: version[0]),
                port:port);
  }
}

exit(0);
