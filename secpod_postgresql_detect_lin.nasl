# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900478");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PostgreSQL Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.postgresql.org/");

  script_tag(name:"summary", value:"SSH login-based detection of PostgreSQL.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

binaries = ssh_find_file(file_name:"/psql$", useregex:TRUE, sock:sock);
foreach binary(binaries) {

  binary = chomp(binary);
  if(!binary)
    continue;

  vers = ssh_get_bin_version(full_prog_name:binary, version_argv:"--version", ver_pattern:"psql \(PostgreSQL\) ([0-9.]+)", sock:sock);
  if(!isnull(vers[1])) {

    set_kb_item(name:"postgresql/detected", value:TRUE);
    set_kb_item(name:"postgresql/ssh-login/detected", value:TRUE);

    cpe = build_cpe(value:vers[1], exp:"^([0-9.]+)", base:"cpe:/a:postgresql:postgresql:");
    if(!cpe)
      cpe = "cpe:/a:postgresql:postgresql";

    register_product(cpe:cpe, location:binary, port:0, service:"ssh-login");

    report = build_detection_report(app:"PostgreSQL", version:vers[1], install:binary, cpe:cpe, concluded:vers[max_index(vers)-1]);
    log_message(port:0, data:report);
  }
}

ssh_close_connection();
exit(0);
