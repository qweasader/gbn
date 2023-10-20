# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804802");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2014-4980");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-08-08 10:33:08 +0530 (Fri, 08 Aug 2014)");
  script_name("Tenable Nessus Web UI Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_mandatory_keys("nessus/installed");

  script_xref(name:"URL", value:"http://www.tenable.com/security/tns-2014-05");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68782");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127532");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/532839/100/0/threaded");

  script_tag(name:"summary", value:"Nessus is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in /server/properties which does not validate
  'token' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain knowledge on
  sensitive information.");

  script_tag(name:"affected", value:"Tenable Web UI before 2.3.5 in Nessus versions 5.2.3 through 5.2.7.");

  script_tag(name:"solution", value:"Upgrade Tenable Web UI component to 2.3.5 in Nessus.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/server/properties?token=";

req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req, bodyonly:FALSE );
if(!res)
  exit(0);

if("loaded_plugin_set" >< res || "scanner_boottime" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
