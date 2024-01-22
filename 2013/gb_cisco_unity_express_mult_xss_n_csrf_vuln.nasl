# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803167");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-1114", "CVE-2013-1120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-02-06 11:33:49 +0530 (Wed, 06 Feb 2013)");
  script_name("Cisco Unity Express Multiple XSS and CSRF Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57678");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24449");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=28044");
  script_xref(name:"URL", value:"http://infosec42.blogspot.in/2013/02/cisco-unity-express-vulnerabilities.html");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1114");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  perform certain actions when a logged-in user visits a specially crafted web page.");

  script_tag(name:"affected", value:"Cisco Unity Express version 7.x");

  script_tag(name:"insight", value:"- Input passed via the 'gui_pagenotableData' parameter to Web/SA2/ScriptList.do
  and 'holiday.description' parameter to /Web/SA3/AddHoliday.do are not
  properly sanitized before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing proper validity checks to verify the requests.");

  script_tag(name:"solution", value:"Upgrade to Cisco Unity Express 8.0 or later.");

  script_tag(name:"summary", value:"Cisco Unity Express is prone to multiple cross-site scripting and request forgery vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = '/Web/SA2/ScriptList.do?gui_pagenotableData=><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(document\.cookie\)</script>", extra_check:make_list('com.cisco.aesop.vmgui',
   'com.cisco.aesop.gui'), check_header:TRUE))
{
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}
