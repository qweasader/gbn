# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900073");
  script_version("2023-04-21T10:20:09+0000");
  script_tag(name:"last_modification", value:"2023-04-21 10:20:09 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenOffice.org Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenOffice.org.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "OpenOffice.org Detection (Linux/Unix SSH Login)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

openName = ssh_find_file(file_name:"/versionrc$", useregex:TRUE, sock:sock);
foreach binaryName(openName) {

  binaryName = chomp(binaryName);
  if(!binaryName || "openoffice" >!< binaryName)
    continue;

  openVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binaryName, ver_pattern:"[0-9]\.[0-9](\.[0-9])?", sock:sock);
  if(openVer[0]) {

    ssh_close_connection();

    set_kb_item(name:"openoffice.org/linux/detected", value:TRUE);

    cpe1 = build_cpe(value:openVer[0], exp:"^([0-9.]+)", base:"cpe:/a:apache:openoffice:");
    cpe2 = build_cpe(value:openVer[0], exp:"^([0-9.]+)", base:"cpe:/a:openoffice:openoffice.org:");
    if(cpe1) {
      register_host_detail(name:"App", value:cpe1, desc:SCRIPT_DESC);
      register_host_detail(name:"App", value:cpe2, desc:SCRIPT_DESC);
    }

    log_message(data:'Detected OpenOffice version: ' + openVer[0] +
                '\nLocation: ' + binaryName +
                '\n\nConcluded from version identification result:\n' +
                 openVer[max_index(openVer)-1]);

    exit(0);
  }
}

ssh_close_connection();
exit(0);
