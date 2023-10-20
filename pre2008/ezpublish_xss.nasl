# SPDX-FileCopyrightText: 2003 k-otik.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:ez:ez_publish';

#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11449");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7138");
  script_cve_id("CVE-2003-0310");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("eZ Publish Cross Site Scripting Bugs");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2003 k-otik.com");
  script_dependencies("sw_ez_publish_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ez_publish/installed");

  script_tag(name:"solution", value:"Upgrade to a newer version.");
  script_tag(name:"summary", value:"eZ Publish 2.2.7  has a cross site scripting bug. An attacker may use it to
 perform a cross site scripting attack on this host.

 In addition to this, another flaw may allow an attacker store hostile
 HTML code on the server side, which will be executed by the browser of the
 administrative user when he looks at the server logs.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE)) exit(0);
if (!dir = get_app_location(cpe: CPE, port: port)) exit(0);

if (dir == "/") dir = "";

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

url = string(dir, "/search/?SectionIDOverride=1&SearchText=<script>window.alert(document.cookie);</script>");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if( isnull( buf ) ) exit( 0 );

if(buf =~ "^HTTP/1\.[01] 200" && "<script>window.alert(document.cookie);</script>" >< buf) {
    security_message(port:port);
    exit(0);
}

exit(99);
