# SPDX-FileCopyrightText: 2005 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11278");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0050", "CVE-2003-0051", "CVE-2003-0052", "CVE-2003-0053", "CVE-2003-0054", "CVE-2003-0055");
  script_name("Quicktime/Darwin Remote Admin Exploit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michael Scheidell");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 1220);
  script_mandatory_keys("QuickTime_Darwin/banner");

  script_xref(name:"URL", value:"http://www.atstake.com/research/advisories/2003/a022403-1.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6955");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6956");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6957");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6958");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6960");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6990");

  script_tag(name:"solution", value:"Obtain a patch or new software from Apple or block this port (TCP 1220) from internet access.");

  script_tag(name:"summary", value:"Cross site scripting, buffer overflow and remote command
  execution on QuickTime/Darwin Streaming Administration Server.");

  script_tag(name:"insight", value:"This is due to parsing problems with per script:

  parse_xml.cgi.

  The worst of these vulnerabilities allows for remote command execution usually as root
  or administrator.

  These servers are installed by default on port 1220.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:1220);
banner = http_get_remote_headers(port:port);
if(!banner || ("QuickTime" >!< banner && "DSS/" >!< banner))
  exit(0);

foreach dir (make_list_unique("/AdminHTML", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/parse_xml.cgi";

  if(http_is_cgi_installed_ka(item:url, port:port)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
