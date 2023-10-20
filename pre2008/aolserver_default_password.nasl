# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10753");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AOLserver Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Default Accounts");
  script_dependencies("gb_aol_server_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("aol/server/detected");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the default username and password on your web server.");

  script_tag(name:"summary", value:"The remote web server is running AOL web server (AOLserver) with
  the default username and password set.");

  script_tag(name:"impact", value:"An attacker may use this to gain control of the remote web server.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/a:aol:aolserver";

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/nstelemetry.adp";
req = string("GET ", url, " HTTP/1.0\r\nAuthorization: Basic bnNhZG1pbjp4\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(ereg(string:res, pattern:"^HTTP/1\.[01] 200") && "AOLserver Telemetry" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
