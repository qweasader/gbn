# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800432");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MIT Kerberos5 Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of MIT Kerberos5.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

files = ssh_find_bin(prog_name:"krb5-config", sock:sock);
foreach file(files) {

  file = chomp(file);
  if(!file)
    continue;

  # Kerberos 5 release 1.15
  # Kerberos 5 release 1.12.1
  # nb: The heimdal variant of krb5-config returns the following which we don't want to catch:
  # heimdal 1.6.99
  vers = ssh_get_bin_version(full_prog_name:file, version_argv:"--version", ver_pattern:"Kerberos 5 [Rr]elease ([0-9.]+)", sock:sock);
  if(vers[1]) {

    set_kb_item(name:"mit/kerberos5/detected", value:TRUE);

    register_and_report_cpe(app:"MIT Kerberos5", ver:vers[1], base:"cpe:/a:mit:kerberos:", expr:"^([0-9.]+)", regPort:0, insloc:file, concluded:vers[0], regService:"ssh-login");
  }
}

ssh_close_connection();
exit(0);
