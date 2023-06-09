###############################################################################
# OpenVAS Vulnerability Test
#
# Interleave Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103111");
  script_version("2020-12-23T12:52:58+0000");
  script_tag(name:"last_modification", value:"2020-12-23 12:52:58 +0000 (Wed, 23 Dec 2020)");
  script_tag(name:"creation_date", value:"2011-03-08 14:02:18 +0100 (Tue, 08 Mar 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Interleave Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.interleave.nl");

  script_tag(name:"summary", value:"HTTP based detection of Interleave.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/interleave", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache(item:url, port:port);
  if(!buf)
    continue;

  if(egrep(pattern:"<title>Interleave Business Process Management", string:buf, icase:TRUE) &&
     "Please enter your username and password" >< buf) {

    set_kb_item(name:"interleave/detected", value:TRUE);

    vers = "unknown";

    url = dir + "/README";
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    version = eregmatch(string:buf, pattern:"Current version is ([0-9.]+)", icase:TRUE);
    if(!isnull(version[1]))
      vers = chomp(version[1]);

    register_and_report_cpe(app:"Interleave", ver:vers, concluded:version[0], base:"cpe:/a:atomos:interleave:", expr:"^([0-9.]+)", insloc:install, regPort:port, conclUrl:url);

    exit(0);
  }
}

exit(0);
