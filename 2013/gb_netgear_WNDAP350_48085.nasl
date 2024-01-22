# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103702");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Netgear WNDAP350 Wireless Access Point Multiple Information Disclosure Vulnerabilities - Active Check");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127112031/https://www.securityfocus.com/bid/48085/");
  script_xref(name:"URL", value:"https://revspace.nl/RevelationSpace/NewsItem11x05x30x0");

  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2013-04-22 13:20:27 +0200 (Mon, 22 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Netgear WNDAP350 wireless access point devices are prone to
  multiple remote information disclosure issues because they fail to restrict access to sensitive
  information.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to obtain sensitive
  information that can aid in launching further attacks.");

  script_tag(name:"affected", value:"Netgear WNDAP350 devices with firmware 2.0.1 and 2.0.9 are
  known to be vulnerable. Other firmware versions may also be affected.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(http_vuln_check(port:port, url:"/index.php?page=master", pattern:"<title>Netgear", usecache:TRUE)) {

  url = "/downloadFile.php";

  if(http_vuln_check(port:port, url:url, pattern:"system:basicSettings:adminPasswd")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
