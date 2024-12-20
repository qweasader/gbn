# SPDX-FileCopyrightText: 2001 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10661");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft IIS 5 '.printer' ISAPI Filter Applied - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/181109");

  script_tag(name:"solution", value:"To unmap the .printer extension:

  1.Open Internet Services Manager.

  2.Right-click the Web server choose Properties from the context menu.

  3.Master Properties

  4.Select WWW Service -> Edit -> HomeDirectory -> Configuration

  and remove the reference to .printer from the list.");

  script_tag(name:"summary", value:"Remote Web server supports Internet Printing Protocol.");

  script_tag(name:"insight", value:"IIS 5 has support for the Internet Printing Protocol(IPP), which is
  enabled in a default install. The protocol is implemented in IIS5 as an ISAPI extension. At least one
  security problem (a buffer overflow) has been found with that extension in the past, so we recommend
  you disable it if you do not use this functionality.");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/NULL.printer";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("Error in web printer install" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  log_message(port:port, data:report);
  exit(0);
}

exit(99);
