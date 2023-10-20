# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808636");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-06 12:39:14 +0530 (Thu, 06 Oct 2016)");
  script_name("IBM Tivoli Storage Manager Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  IBM Tivoli Storage Manager on Linux.

  The script logs in via ssh, searches for tivoli and queries the
  version from 'README_enu.htm' file.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if(!paths = ssh_find_file(file_name:"/README_enu\.htm$", useregex:TRUE, sock:sock))
  exit(0);

foreach binary_name(paths)
{

  binary_name = chomp(binary_name);
  if(!binary_name)
    continue;

  bracVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binary_name, ver_pattern:'Tivoli Storage Manager Backup-Archive Client Version ([0-9.]+)', sock:sock);

  if(bracVer[1] != NULL)
  {
    set_kb_item(name:"IBM/Tivoli/Storage/Manager/Linux/Ver", value:bracVer[1]);

    cpe = build_cpe(value:bracVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_storage_manager:");
    if(!cpe)
      cpe = "cpe:/a:ibm:tivoli_storage_manager";

    register_product(cpe:cpe, location:paths[0]);
    log_message(data: build_detection_report(app:"IBM Tivoli Storage Manager Client",
                                             version: bracVer[1],
                                             install: binary_name,
                                             cpe: cpe,
                                             concluded: bracVer[1]));
    exit(0);
  }
}
ssh_close_connection();
