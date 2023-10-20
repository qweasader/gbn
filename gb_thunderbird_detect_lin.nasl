# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800018");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mozilla Thunderbird Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves Mozilla Thunderbird Version.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

birdName = ssh_find_file(file_name:"/thunderbird$", useregex:TRUE, sock:sock);
if(!birdName) {
  ssh_close_connection();
  exit(0);
}

baseCPE = "cpe:/a:mozilla:thunderbird:";

foreach binary_birdName(birdName) {

  binary_name = chomp(binary_birdName);
  if(!binary_name)
    continue;

  #Examples for versions:
  #9.0a1
  #10.0.3esr
  #11.0
  #24.0b2
  #1.5 RC1
  #1.0
  #Example of returned version: Thunderbird 60.8.0
  birdVer = ssh_get_bin_version(full_prog_name:binary_name, version_argv:"-v", ver_pattern:"Thunderbird\s([0-9]+\.[0-9.]+(\s?[a-zA-Z]+[0-9]*)?)", sock:sock);
  if(birdVer[1]) {

    set_kb_item(name:"Thunderbird/Linux/Ver", value:birdVer[1]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);

    cpeVer = str_replace(string:birdVer[1], find:" ", replace:".");
    CPE = baseCPE + cpeVer;

    register_product(cpe:CPE, location:binary_birdName, service:"ssh-login", port:0);

    log_message(data:build_detection_report(app:"Mozilla Thunderbird (Linux)",
                                            version:birdVer[1],
                                            install:binary_birdName,
                                            cpe:CPE,
                                            concluded:birdVer[0]));
    break;
  }
}

ssh_close_connection();
exit(0);
