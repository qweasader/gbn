# SPDX-FileCopyrightText: 1999 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10247");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0095");
  script_name("Sendmail DEBUG");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 1999 Renaud Deraison");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"Your MTA accepts the DEBUG mode.");

  script_tag(name:"insight", value:"This mode is dangerous as it allows remote users
  to execute arbitrary commands as root without the need to log in.");

  script_tag(name:"solution", value:"Reconfigure or upgrade your MTA.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

res = smtp_recv_banner(socket:soc);
if(!res || "endmail" >!< res) {
  smtp_close(socket:soc, check_data:res);
  exit(0);
}

req = string("DEBUG\r\n");
send(socket:soc, data:req);
res = smtp_recv_line(socket:soc, code:"200");
smtp_close(socket:soc, check_data:res);

if("200 debug set" >< tolower(res)) {
  report = 'The remote SMTP service accepts the DEBUG command. Answer:\n\n' + res;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);