# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804654");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-4301");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-07-01 11:38:34 +0530 (Tue, 01 Jul 2014)");
  script_name("Eugene Ajenti 'respond_error' Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Eugene Ajenti is prone to multiple cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"The flaws exist due to 'respond_error' function in routing.py which does not
  validate input passed via the URL to resources.js and resources.css before
  returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Eugene Pankov Ajenti before version 1.2.21.7.");

  script_tag(name:"solution", value:"Upgrade to Eugene Pankov Ajenti version 1.2.21.7 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68047");
  script_xref(name:"URL", value:"https://www.netsparker.com/critical-xss-vulnerabilities-in-ajenti");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

ajentiPort = http_get_port(default:8000);

res = http_get_cache(item:"/", port:ajentiPort);

if(res && ">Ajenti<" >< res && "login" >< res)
{
  url = "/ajenti:static/resources.js%3Cscript%3Ealert%28document.cook" +
        "ie%29%3C/script%3E" ;

  req = http_get(item:url, port:ajentiPort);
  res = http_keepalive_send_recv(port:ajentiPort, data:req, bodyonly:FALSE);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res)
  {
    security_message(port:ajentiPort);
    exit(0);
  }
}

exit(99);
