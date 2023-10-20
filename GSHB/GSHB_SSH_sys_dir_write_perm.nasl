# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96081");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Check write permissions of system directories");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses SSH to check write permissions of system
  directories.");

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
  set_kb_item(name: "GSHB/Dir-Writeperm", value:"error");
  set_kb_item(name: "GSHB/Dir-Writeperm/log", value:error);
  exit(0);
}

writeperm = ssh_cmd(socket:sock, cmd:"find / -mount -type d -perm -002");

if (!writeperm) writeperm = "none";
else if(writeperm != "none"){
  Lst = split(writeperm, keep:FALSE);
  if (Lst){
    for (i=0; i<max_index(Lst); i++){
      if ("/home/" >< Lst[i] || "/tmp" >< Lst[i] || Lst[i] =~ ".*(Keine Berechtigung|Permission denied).*") continue;
      ClearLst +=  Lst[i] + '\n';
    }
  }else if ("/home/" >!< Lst[i] && "/tmp" >!< Lst[i] && Lst[i] !~ ".*(Keine Berechtigung|Permission denied).*") Clearlist = writeperm;
}

if ("FIND: Invalid switch" >< ClearLst || "FIND: Parameterformat falsch" >< ClearLst) ClearLst = "windows";
else if (ClearLst =~ "(F|f)(I|i)(N|n)(D|d): .*") ClearLst = "nofind";
else if (!ClearLst) ClearLst = "none";

set_kb_item(name: "GSHB/Dir-Writeperm", value:ClearLst);

exit(0);
