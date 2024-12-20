# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14226");
  script_version("2023-12-29T16:09:56+0000");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpBB Fetch All < 2.0.12 SQLi Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210218080048/http://www.securityfocus.com/bid/10868");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210207004858/http://www.securityfocus.com/bid/10893");
  script_xref(name:"OSVDB", value:"8353");

  script_tag(name:"summary", value:"phpBB Fetch All is prone to a SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is reported that this version of phpBB Fetch All is
  susceptible to an SQL injection vulnerability. This issue is due to a failure of the application
  to properly sanitize user-supplied input before using it in an SQL query.

  The successful exploitation of this vulnerability depends on the implementation of the web
  application that includes phpBB Fetch All as a component. It may or may not be possible to
  effectively pass malicious SQL statements to the underlying function.");

  script_tag(name:"impact", value:"Successful exploitation could result in compromise of the
  application, disclosure or modification of data or may permit an attacker to exploit
  vulnerabilities in the underlying database implementation.");

  script_tag(name:"affected", value:"phpBB Fetch All versions prior to 2.0.12.");

  script_tag(name:"solution", value:"Update to version 2.0.12 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php";
res = http_get_cache(item:url, port:port);
if(!res)
  exit(0);

if(ereg(pattern:"Fetch by phpBB Fetch All ([01]\..*|2\.0\.([0-9]|1[01])[^0-9])", string:res)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
