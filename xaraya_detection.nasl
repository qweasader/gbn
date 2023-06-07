###############################################################################
# OpenVAS Vulnerability Test
#
# Authors:
# Josh Zlatin-Amishav
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19426");
  script_version("2022-09-09T10:12:35+0000");
  script_tag(name:"last_modification", value:"2022-09-09 10:12:35 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Xaraya Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.xaraya.com/");

  script_tag(name:"summary", value:"HTTP based detection of Xaraya.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/xaraya", http_cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);
  if (!res)
    continue;

  if (egrep(string:res, pattern:"^[Ss]et-[Cc]ookie\s*:\s*XARAYASID=", icase:FALSE) || # Cookie from Xaraya
      egrep(string:res, pattern:"^[Xx]-[Mm]eta-[Gg]enerator\s*:\s*Xaraya ::", icase:FALSE) || # Meta tag from Xaraya
      'meta name="Generator" content="Xaraya ::' >< res ||
      egrep(string:res, pattern:'div class="xar-(alt|block-.+|menu-.+|norm)"') ) { # Xaraya look-and-feel

   # Look for the version number in a meta tag.
   pat = 'meta name="Generator" content="Xaraya :: ([^"]+)';
   matches = egrep(pattern:pat, string:res);
   if (matches) {
     foreach match (split(matches)) {
       ver = eregmatch(pattern:pat, string:match);
       if (!isnull(ver)) {
         ver = ver[1];
         info = string("Xaraya version ", ver, " is installed on the remote host\nunder the path ", install, ".");
         break;
       }
     }
   }

   if (isnull(ver)) {
     ver = "unknown";
     info = string("An unknown version of Xaraya is installed on the remote host\nunder the path ", install, ".");
   }

   set_kb_item(name:"www/" + port + "/xaraya", value:ver + " under " + install);
   report = '\n\nPlugin output :\n\n' + info;
   log_message(port:port, data:report);
   exit(0);
  }
}
