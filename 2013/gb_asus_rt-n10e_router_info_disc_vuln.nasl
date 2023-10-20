# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803769");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-3610");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-10 13:46:03 +0530 (Thu, 10 Oct 2013)");
  script_name("ASUS RT-N10E Wireless Router Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"ASUS RT-N10E Wireless Router is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send direct HTTP GET request and check it is possible to read the password
  and other information or not.");

  script_tag(name:"solution", value:"Upgrade to ASUS Wireless-N150 Router RT-N10E firmware 2.0.0.25 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"The flaw is due to the device not properly restricting access to the
  '/qis/QIS_finish.htm' page.");

  script_tag(name:"affected", value:"ASUS Wireless-N150 Router RT-N10E firmware versions 2.0.0.24 and earlier.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to disclose certain
  sensitive information.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62850");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/984366");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("RT-N10E/banner");

  script_xref(name:"URL", value:"http://www.asus.com/Networking/RTN10E/#support_Download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port: port);
if(banner && 'WWW-Authenticate: Basic realm="RT-N10E"' >!< banner){
  exit(0);
}

url = "/qis/QIS_finish.htm";

if(http_vuln_check(port:port, url:url,
   pattern:"ASUS Wireless Router",
   extra_check:make_list("password_item",
   "account_item", "#wanip_item")))
{
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}
