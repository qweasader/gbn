# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813613");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-25 12:43:58 +0530 (Mon, 25 Jun 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Burp Suite Community Edition Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  Burp Suite Community Edition.

  The script logs in via ssh, searches for executable 'BurpSuiteCommunity' and queries
  the found executables via command line option '--version'");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

burp_sock = ssh_login_or_reuse_connection();
if(!burp_sock) exit( 0 );

burpName = ssh_find_file(file_name:"/BurpSuiteCommunity$", useregex:TRUE, sock:burp_sock);

foreach binaryName (burpName)
{
  binaryName = chomp(binaryName);
  if(!binaryName)
    continue;

  burpVer = ssh_get_bin_version(full_prog_name:binaryName, sock:burp_sock, version_argv:"--version", ver_pattern:"([0-9.-]+) Burp Suite Community Edition");
  if(burpVer[1] != NULL)
  {
    set_kb_item(name:"BurpSuite/CE/Linux/Ver", value:burpVer[1]);

    cpe = build_cpe(value: burpVer[1], exp:"^([0-9.-]+)", base:"cpe:/a:portswigger:burp_suite:");
    if(isnull(cpe))
      cpe = 'cpe:/a:portswigger:burp_suite';

    register_product(cpe:cpe, location:binaryName);

    log_message(data:build_detection_report(app: "Burp Suite Community Edition",
                                             version: burpVer[1],
                                             install: binaryName,
                                             cpe: cpe,
                                             concluded: burpVer[1]));
  }
}
ssh_close_connection();
