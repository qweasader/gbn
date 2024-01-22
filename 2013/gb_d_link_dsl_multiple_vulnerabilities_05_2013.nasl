# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103706");
  script_version("2024-01-09T05:06:46+0000");
  script_name("D-Link DSL-320B Multiple Security Vulnerabilities - Active Check");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_xref(name:"URL", value:"https://web.archive.org/web/20221203162240/http://www.s3cur1ty.de/m1adv2013-018");
  script_xref(name:"URL", value:"http://www.dlink.com/de/de/home-solutions/connect/modems-and-gateways/dsl-320b-adsl-2-ethernet-modem");

  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2013-05-06 12:58:41 +0200 (Mon, 06 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("micro_httpd/banner");

  script_tag(name:"summary", value:"D-Link DSL-320B devices are prone multiple security
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Access to the config file without authentication

  - Access to the logfile without authentication

  - Stored cross-site scripting (XSS) within parental control");

  script_tag(name:"impact", value:"An attacker can exploit these issues to gain access to
  potentially sensitive information, decrypt stored passwords, steal cookie-based authentication
  credentials.");

  script_tag(name:"solution", value:"A firmware update is available.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(banner && banner !~ "Server\s*:\s*micro_httpd")
  exit(0);

if(http_vuln_check(port:port, url:"/", pattern:"DSL-", usecache:TRUE)) {

  if(http_vuln_check(port:port, url:"/config.bin", pattern:"sysPassword", extra_check:"sysUserName")) {
    report = http_report_vuln_url(port:port, url:"/config.bin");
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
