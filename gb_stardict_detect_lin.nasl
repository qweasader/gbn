# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800643");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("StarDict Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of StarDict.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "StarDict Version Detection (Linux)";

stardict_sock = ssh_login_or_reuse_connection();
if(!stardict_sock)
  exit(0);

paths = ssh_find_bin(prog_name:"stardict", sock:stardict_sock);
foreach stardictbin (paths)
{

  stardictbin = chomp(stardictbin);
  if(!stardictbin)
    continue;

  stardictVer = ssh_get_bin_version(full_prog_name:stardictbin, sock:stardict_sock, version_argv:"--version", ver_pattern:"stardict ([0-9._]+)");
  if(stardictVer[1] != NULL)
  {
    set_kb_item(name:"StarDict/Linux/Ver", value:stardictVer[1]);
    log_message(data:"StarDict version " + stardictVer[1] + " running at location " + stardictbin + " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:stardictVer[1], exp:"^([0-9.]+)", base:"cpe:/a:stardict:stardict:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
