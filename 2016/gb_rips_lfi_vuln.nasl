# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rips_scanner:rips";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806808");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-01-06 12:48:22 +0530 (Wed, 06 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Rips Scanner Multiple Directory Listing Vulnerabilities");

  script_tag(name:"summary", value:"Rips scanner 0.55 is prone to multiple local file inclusion vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
 check whether it is able to get the content of local php files.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper
 validation of user supplied input to 'file' parameter in code.php and
 function.php scripts");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
 attackers to gain access to local php files and to compromise the application.");

  script_tag(name:"affected", value:"Rips scanner version 0.55");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39094/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135066/ripsscanner05-disclose.txt");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_rips_detect.nasl");
  script_mandatory_keys("rips/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!rips_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:rips_port)){
  exit(0);
}

url = dir + "/windows/function.php?file=leakscan.php&start=0&end=40";

if(http_vuln_check(port:rips_port, url:url, check_header:TRUE,
   pattern:"./config/securing.php", extra_check:"securing functions" ))
{
  report = http_report_vuln_url( port:rips_port, url:url );
  security_message(port:rips_port, data:report);
  exit(0);
}
