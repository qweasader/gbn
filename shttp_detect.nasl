# OpenVAS Vulnerability Test
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

# nb: Vulnerability reporting has been moved into a dedicated pre2008/shttp_reporting.nasl

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11720");
  script_version("2022-08-03T10:11:15+0000");
  script_tag(name:"last_modification", value:"2022-08-03 10:11:15 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Secure HyperText Transfer Protocol (S-HTTP) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  # nb: No "httpver.nasl" dependency as we don't need to know the HTTP version supported by the target.
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  # RFC 2660 The Secure HyperText Transfer Protocol
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc2660");

  script_tag(name:"summary", value:"Detection of services supporting the Secure HyperText Transfer
  Protocol (S-HTTP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
host = http_host_name(port:port);

if(!soc = http_open_socket(port))
  exit(0);

req = string("Secure * Secure-HTTP/1.4\r\n",
             "Host: ", host, "\r\n",
             "Connection: close\r\n",
             "\r\n");
send(socket:soc, data:req);
res = recv_line(socket:soc, length:256);
http_close_socket(soc);
if(!res)
  exit(0);

if(concl = egrep(pattern:"Secure-HTTP/[0-9]\.[0-9] 200", string:res, icase:FALSE)) {

  set_kb_item(name:"shttp/detected", value:TRUE);
  set_kb_item(name:"shttp/" + port + "/detected", value:TRUE);

  banner = chomp(concl);
  set_kb_item(name:"shttp/" + port + "/banner", value:banner);

  report = 'Received banner:\n\n' + banner;
  log_message(port:port, data:report);
}

exit(0);
