# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:neocrome:land_down_under";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19678");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2674", "CVE-2005-2675", "CVE-2005-2780");
  script_xref(name:"OSVDB", value:"19298");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Land Down Under <= 800 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("ldu_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ldu/detected");

  script_tag(name:"solution", value:"Upgrade to Land Down Under version 801 or later.");

  script_tag(name:"summary", value:"The remote version of Land Down Under is prone to various SQL injection and
  cross-site scripting attacks provided PHP's 'magic_quotes' setting is disabled due to its failure to sanitize the
  request URI before using it in 'system/functions.php' in the function 'ldu_log()'. A malicious user may be able
  to exploit this issue to manipulate SQL queries, steal authentication cookies, and the like.

  In addition, it also fails to properly sanitize the user-supplied signature in forum posts. A malicious user can
  exploit this vulnerability to steal authentication cookies and manipulate the HTML format in 'forums.php'.");

  script_xref(name:"URL", value:"http://www.securityfocus.org/archive/1/408664");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14619");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14677");
  script_xref(name:"URL", value:"http://www.neocrome.net/forums.php?m=posts&p=83412#83412");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0395.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

req = http_get(item: dir + "/index.php?m='", port: port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if (egrep(string:res, pattern:string("MySQL error.+syntax to use near '"))) {
  security_message(port);
  exit(0);
}

exit(99);