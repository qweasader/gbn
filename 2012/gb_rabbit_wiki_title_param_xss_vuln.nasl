# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802608");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-13 15:15:15 +0530 (Mon, 13 Feb 2012)");
  script_name("RabbitWiki 'title' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51971");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109628/rabbitwiki-xss.txt");
  script_xref(name:"URL", value:"http://st2tea.blogspot.in/2012/02/rabbitwiki-cross-site-scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"RabbitWiki");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied
  input to the 'title' parameter in 'index.php', which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"RabbitWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/RabbitWiki", "/wiki", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port: port);

  if(!isnull(res) && '>RabbitWiki<' >< res)
  {
    url = dir + "/index.php?title=<script>alert(/xss-test/)</script>";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"<script>alert\(/xss-test/\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
