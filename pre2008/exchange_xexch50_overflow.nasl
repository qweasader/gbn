# SPDX-FileCopyrightText: 2003 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11889");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2003-A-0031");
  script_cve_id("CVE-2003-0714");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Exchange XEXCH50 Remote Buffer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Digital Defense Inc.");
  script_family("SMTP problems");
  script_dependencies("sw_ms_exchange_server_remote_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/smtp/detected");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8838");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This system appears to be running a version of the Microsoft Exchange
  SMTP service that is vulnerable to a flaw in the XEXCH50 extended verb.");

  script_tag(name:"impact", value:"This flaw can be used to completely crash Exchange 5.5 as well as execute
  arbitrary code on Exchange 2000.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(smtp_get_is_marked_wrapped(port:port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

greeting = smtp_recv_banner(socket:soc);
if(!egrep(string:greeting, pattern:"microsoft", icase:TRUE))
  exit(0);

send(socket:soc, data:string("EHLO X\r\n"));
ok = smtp_recv_line(socket:soc);
if(!ok || "XEXCH50" >!< ok) {
  smtp_close(socket:soc, check_data:ok);
  exit(0);
}

send(socket:soc, data:string("MAIL FROM: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if(!ok) {
  smtp_close(socket:soc, check_data:ok);
  exit(0);
}

send(socket:soc, data:string("RCPT TO: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if(!ok) {
  smtp_close(socket:soc, check_data:ok);
  exit(0);
}

send(socket:soc, data:string("XEXCH50 2 2\r\n"));
ok = smtp_recv_line(socket:soc);
smtp_close(socket:soc, check_data:ok);
if(!ok)
  exit(0);

if(egrep(string:ok, pattern:"^354 Send binary")) {
  security_message(port:port);
  exit(0);
}

exit(99);
