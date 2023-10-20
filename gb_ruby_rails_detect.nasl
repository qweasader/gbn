# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800911");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Ruby on Rails Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Ruby on Rails.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

paths = ssh_find_file( file_name: "/rails$", useregex: TRUE, sock: sock );
foreach bin( paths ) {

  bin = chomp( bin );
  if( ! bin )
    continue;

  vers = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-v", ver_pattern: "Rails ([0-9.]+)" );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name: "rails/detected", value: TRUE );
    set_kb_item( name: "rails/ssh-login/detected", value: TRUE );
    set_kb_item( name: "rails/ssh-login/port", value: "22" );
    set_kb_item( name: "rails/ssh-login/22/install", value: "22#---#" + bin + "#---#" + version + "#---#" + vers[0] );
  }
}

ssh_close_connection();

exit( 0 );
