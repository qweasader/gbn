###############################################################################
# OpenVAS Vulnerability Test
#
# phpScheduleIt Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100233");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-07-20 17:00:58 +0200 (Mon, 20 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("phpScheduleIt Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running phpScheduleIt, an Open Source web-based
  reservation and scheduling system.");

  script_xref(name:"URL", value:"http://www.php.brickhost.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "phpScheduleIt Detection";

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/conference", "/schedule", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = string(dir, "/roschedule.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( ! buf ) continue;

 if(egrep(pattern: "phpScheduleIt v[0-9.]+", string: buf, icase: TRUE))
 {
    vers = string("unknown");
    version = eregmatch(string: buf, pattern: "phpScheduleIt v([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/phpScheduleIt"), value: tmp_version);
    set_kb_item(name: "phpscheduleit/detected", value: TRUE);

    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:php.brickhost:phpscheduleit:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    info = string("phpScheduleIt Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
