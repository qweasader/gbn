# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96085");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-26 16:31:33 +0200 (Mon, 26 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("List /var/adm and /lar/log accessrights, read /etc/rsylog.conf an /etc/syslog.conf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"List /var/adm and /lar/log accessrights, read /etc/rsylog.conf an /etc/syslog.conf");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = get_preference("auth_port_ssh");
if(!port)
  port = ssh_get_port(default:22, ignore_unscanned:TRUE);

sock = ssh_login_or_reuse_connection();
if(!sock) {
    error = ssh_get_error();
    if (!error) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name: "GSHB/var_log", value:"error");
    set_kb_item(name: "GSHB/var_adm", value:"error");
    set_kb_item(name: "GSHB/syslog", value:"error");
    set_kb_item(name: "GSHB/rsyslog", value:"error");
    set_kb_item(name: "GSHB/syslog", value:"error");
    set_kb_item(name: "GSHB/syslogr", value:"error");
    set_kb_item(name: "GSHB/rsyslog", value:"error");
    set_kb_item(name: "GSHB/rsyslogr", value:"error");
    set_kb_item(name: "GSHB/rsyslog/log", value:error);

    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/var_log", value:"windows");
    set_kb_item(name: "GSHB/var_adm", value:"windows");
    set_kb_item(name: "GSHB/syslog", value:"windows");
    set_kb_item(name: "GSHB/rsyslog", value:"windows");
    set_kb_item(name: "GSHB/syslog", value:"windows");
    set_kb_item(name: "GSHB/syslogr", value:"windows");
    set_kb_item(name: "GSHB/rsyslog", value:"windows");
    set_kb_item(name: "GSHB/rsyslogr", value:"windows");
  exit(0);
}

var_log = ssh_cmd(socket:sock, cmd:"LANG=C ls -ld /var/log");
var_adm = ssh_cmd(socket:sock, cmd:"LANG=C ls -ld /var/adm");
syslog_r = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/syslog.conf");
rsyslog_r = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/rsyslog.conf");
syslog = ssh_cmd(socket:sock, cmd:"LANG=C ls /var/run/syslogd.");
rsyslog = ssh_cmd(socket:sock, cmd:"LANG=C ls /var/run/rsyslogd.");

syslog = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/syslog.conf");
rsyslog = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/rsyslog.conf");

if (var_log =~ ".*such.file.*directory.*") var_log = "none";
if (var_adm =~ ".*such.file.*directory.*") var_adm = "none";
if (syslog_r =~ ".*such.file.*directory.*") syslog_r = "none";
if (rsyslog_r =~ ".*such.file.*directory.*") rsyslog_r = "none";

if (syslog =~ ".*such.file.*directory.*") syslog = "off";
else syslog = "running";
if (rsyslog =~ ".*such.file.*directory.*") rsyslog = "off";
else rsyslog = "running";

if (var_log != "none"){
  Lst = split (var_log, sep:" ", keep:0);
  var_log = Lst[0] + ":" + Lst[2]+ ":" + Lst[3];
}
if (var_adm != "none"){
  Lst = split (var_adm, sep:" ", keep:0);
  var_adm = Lst[0] + ":" + Lst[2]+ ":" + Lst[3];
}
if (syslog_r != "none"){
  Lst = split (syslog_r, sep:" ", keep:0);
  syslog_r = Lst[0] + ":" + Lst[2]+ ":" + Lst[3];
}
if (rsyslog_r != "none"){
  Lst = split (rsyslog_r, sep:" ", keep:0);
  rsyslog_r = Lst[0] + ":" + Lst[2]+ ":" + Lst[3];
}

if (syslog =~ ".*Permission denied.*") syslog = "norights";
if (syslog =~ ".*such.file.*directory.*") syslog = "none";

if (rsyslog =~ ".*Permission denied.*") rsyslog = "norights";
if (rsyslog =~ ".*such.file.*directory.*") rsyslog = "none";

set_kb_item(name: "GSHB/var_log", value:var_log);
set_kb_item(name: "GSHB/var_adm", value:var_adm);
set_kb_item(name: "GSHB/syslog", value:syslog);
set_kb_item(name: "GSHB/rsyslog", value:rsyslog);
set_kb_item(name: "GSHB/syslogr", value:syslog_r);
set_kb_item(name: "GSHB/rsyslogr", value:rsyslog_r);
set_kb_item(name: "GSHB/syslog", value:syslog);
set_kb_item(name: "GSHB/rsyslog", value:rsyslog);

exit(0);

