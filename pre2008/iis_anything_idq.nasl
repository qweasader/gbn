# SPDX-FileCopyrightText: 2000 Filipe Custodio
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10492");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1065");
  script_cve_id("CVE-2000-0071");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS IDA/IDQ Path Disclosure Vulnerability - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Filipe Custodio");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"Select 'Preferences ->Home directory ->Application',
  and check the checkbox 'Check if file exists' for the ISAPI mappings of your server.");

  script_tag(name:"summary", value:"IIS 4.0 allows a remote attacker to obtain the real pathname
  of the document root by requesting non-existent files with .ida or .idq extensions.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more information about
  the remote host, and hence make more focused attacks.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/anything.idq";
req = http_get(item:url, port:port);
r = http_send_recv(port:port, data:req);

str = egrep(pattern:"^<HTML>", string:r) - "<HTML>";
str = tolower(str);

if(egrep(pattern:"[a-z]\:\\.*anything", string:str)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
} else {
  url = "/anything.ida";
  req = http_get(item:url, port:port);
  r = http_send_recv(port:port, data:req);
  str = egrep(pattern:"^<HTML>", string:r) - "<HTML>";
  str = tolower(str);
  if(egrep(pattern:"[a-z]\:\\.*anything", string:str)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
