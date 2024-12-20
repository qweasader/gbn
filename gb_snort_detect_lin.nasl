# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801138");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Snort Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Snort.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Snort Version Detection (Linux)";

snortSock = ssh_login_or_reuse_connection();
if(!snortSock)
  exit(0);

paths = ssh_find_bin(prog_name:"snort",sock:snortSock);
foreach binName (paths)
{

  binName = chomp(binName);
  if(!binName)
    continue;

  snortVer = ssh_get_bin_version(full_prog_name:binName, version_argv:"-V", ver_pattern:"> Snort! <", sock:snortSock);
  snortVer = eregmatch(pattern:"Version ([0-9.]+)( \(Build.?([0-9]+)\))?", string:snortVer[1], icase:1);
  if(snortVer[1])
  {
    set_kb_item(name:"Snort/Linux/Ver", value:snortVer[1]);
    if(snortVer[3])
    {
      snortVer = snortVer[1] + "." + snortVer[3];
      set_kb_item(name:"Snort/Linux/Build", value:snortVer);
      log_message(data:"Snort version " + snortVer + " running at location " + binName + " was detected on the host");

      cpe = build_cpe(value:snortVer, exp:"^([0-9.]+)", base:"cpe:/a:snort:snort:");
      if(!isnull(cpe))
        register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
    }
  }
}
ssh_close_connection();
