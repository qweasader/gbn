# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pfsense:pfsense";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808587");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-19 12:17:57 +0530 (Tue, 19 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("pfSense Squid Multiple Vulnerabilities");

  script_tag(name:"summary", value:"squid running on pfSense is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper
  escaping of variables in 'squid-monitor.php' and 'squid_clwarn.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser as well as any administrators
  viewing the log files through the pfSense web-GUI.");

  script_tag(name:"affected", value:"Squid Version 0.4.16_2 running on pfSense
  Version 2.3.1-RELEASE-p1");

  script_tag(name:"solution", value:"Upgrade to Squid Version 0.4.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/43");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137526");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pfsense_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("pfsense/http/installed");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE, service:"www")){
  exit(0);
}

url = "/squid_clwarn.php";
req1 = http_get(item:url, port:http_port);
res1 = http_send_recv(port:http_port, data:req1);

if(res1 && res1 =~ "Powered by.*>SquidClamav")
{
  url = '/squid_clwarn.php?url=xyz&source=xyz&user=&virus=' +
        'stream:<script>alert(document.cookie)</script>';

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
     pattern:"Powered by.*>SquidClamav",
     extra_check:make_list("<script>alert\(document.cookie\)</script>",
                           "Virus detected", "Virus name")))
  {
    report = http_report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}
