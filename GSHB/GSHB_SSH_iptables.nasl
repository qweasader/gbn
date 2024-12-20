# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96072");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-07 13:23:53 +0200 (Mon, 07 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("List iptables ruleset");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to List List iptables ruleset.");

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
    set_kb_item(name: "GSHB/iptables/ruleset", value:"error");
    set_kb_item(name: "GSHB/iptables/targets", value:"error");
    set_kb_item(name: "GSHB/iptables/names", value:"error");
    set_kb_item(name: "GSHB/iptables/matches", value:"error");
    set_kb_item(name: "GSHB/iptables/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/iptables/ruleset", value:"windows");
    set_kb_item(name: "GSHB/iptables/targets", value:"windows");
    set_kb_item(name: "GSHB/iptables/names", value:"windows");
    set_kb_item(name: "GSHB/iptables/matches", value:"windows");
  exit(0);
}

uname = ereg_replace(pattern:'\n',replace:'', string:uname);

if (uname !~ "SunOS .*"){
  ruleset = ssh_cmd(socket:sock, cmd:"iptables -L");

  if ("iptables: command not found" >< ruleset || "Befehl wurde nicht gefunden" >< ruleset) ruleset="notfound";
  else if ("Permission denied (you must be root)" >< ruleset) ruleset="noperm";
  else if ("superuser" >< ruleset) ruleset="noperm";
  else if (!ruleset)ruleset="notfound";

  if (ruleset == "notfound" || ruleset == "noperm"){
    targets = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /proc/net/ip_tables_targets");
    names = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /proc/net/ip_tables_names");
    matches = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /proc/net/ip_tables_matches");

    if (targets =~ ".*No such file or directory.*") targets = "notfound";
    if (names =~ ".*No such file or directory.*") names = "notfound";
    if (matches =~ ".*No such file or directory.*") matches = "notfound";

    if (!targets) targets = "none";
    if (!names) names = "none";
    if (!matches) matches = "none";
  }

  set_kb_item(name: "GSHB/iptables/ruleset", value:ruleset);
  set_kb_item(name: "GSHB/iptables/targets", value:targets);
  set_kb_item(name: "GSHB/iptables/names", value:names);
  set_kb_item(name: "GSHB/iptables/matches", value:matches);
}
else if(uname =~ "SunOS .*"){
  ipfilter = ssh_cmd(socket:sock, cmd:"LANG=C /usr/sbin/ipf -V");
  ipfilterstat = ssh_cmd(socket:sock, cmd:"LANG=C /usr/sbin/ipfstat -io");

  if (ipfilter =~ ".*Permission denied.*") ipfilter = "noperm";
  else if (ipfilter =~ ".*not found.*" ) ipfilter = "notfound";
  else{
    if (ipfilter){
      Lst = split(ipfilter, keep:0);
      for(i=0; i<max_index(Lst); i++){
        if (Lst[i] !~ '^Running:.*')continue;
        else if (Lst[i] =~ '^Running:.no.*')ipfilters = "off";
        else if (Lst[i] =~ '^Running:.yes.*')ipfilters = "on";
        else ipfilters = "error";
      }
    }
  }
  if (ipfilterstat =~ ".*Permission denied.*") ipfilterstat = "noperm";
  else if (ipfilterstat =~ ".*not found.*") ipfilterstat = "notfound";
  else{
    if (ipfilterstat){
      Lst = split(ipfilterstat, keep:0);
      for(i=0; i<max_index(Lst); i++){
        if (Lst[i] =~ '^empty list for ipfilter.out.*')out = "nofilter";
        if (Lst[i] =~ '^empty list for ipfilter.in.*')in = "nofilter";
      }
    }
  }
  if (out == "nofilter" && in == "nofilter")ipfilterstat = "nofilter";
  set_kb_item(name: "GSHB/iptables/uname", value:uname);
  set_kb_item(name: "GSHB/iptables/ipfilter", value:ipfilters);
  set_kb_item(name: "GSHB/iptables/ipfilterstat", value:ipfilterstat);
}

exit(0);
