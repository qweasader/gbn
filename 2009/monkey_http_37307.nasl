# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100397");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Monkey HTTP Daemon Invalid HTTP 'Connection' Header Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37307");
  script_xref(name:"URL", value:"http://groups.google.com/group/monkeyd/browse_thread/thread/055b4e9b83973861/c0e013d166ae1eb3?show_docid=c0e013d166ae1eb3");
  script_xref(name:"URL", value:"http://census-labs.com/news/2009/12/14/monkey-httpd/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508442");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Monkey/banner");
  script_require_ports("Services/www", 2001);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available, please see the references for more information.");

  script_tag(name:"summary", value:"Monkey HTTP Daemon is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the application to
  crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Monkey HTTP Daemon 0.9.3 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:2001);
banner = http_get_remote_headers(port: port);
if(!banner)exit(0);

if("Server: Monkey/" >!< banner)exit(0);
version = eregmatch(pattern: "Server: Monkey/([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version: "0.9.3")) {
  report = report_fixed_ver(installed_version:version[1], fixed_version:"0.9.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
