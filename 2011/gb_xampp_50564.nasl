# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apachefriends:xampp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103336");
  script_version("2024-06-18T05:05:55+0000");
  script_tag(name:"last_modification", value:"2024-06-18 05:05:55 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-11-08 09:38:06 +0100 (Tue, 08 Nov 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("XAMPP <= 1.7.7 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xampp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("xampp/http/detected", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"XAMPP is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"XAMPP version 1.7.7 and probably prior on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50564");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5054.php");

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

url = dir + '/perlinfo.pl/"><script>alert(/vt-xss-test/)</script>';

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(/vt-xss-test/\)</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
