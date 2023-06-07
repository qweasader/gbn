# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.901084");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AlefMentor Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running AlefMentor version.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

amPort = http_get_port(default:80);

if( !http_can_host_php( port:amPort ) ) exit( 0 );

foreach path (make_list_unique("/", "/am", "/AM", http_cgi_dirs(port:amPort)))
{

  install = path;
  if( path == "/" ) path = "";

  rcvRes = http_get_cache(item: path + "/index.php", port:amPort);

  if("AlefMentor" >< rcvRes)
  {

    version = "unknown";

    amVer = eregmatch(pattern:"AlefMentor ([0-9.]+)" , string:rcvRes);

    if(amVer[1] != NULL) version = amVer[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + amPort + "/AlefMentor", value:tmp_version);
    set_kb_item(name:"alefmentor/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:findmysoft:alefmentor:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:findmysoft:alefmentor';

    register_product( cpe:cpe, location:install, port:amPort, service:"www" );

    log_message( data: build_detection_report( app:"AlefMentor",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:amVer[0]),
                                               port:amPort);

  }
}
