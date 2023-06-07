# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800017");
  script_version("2022-03-02T08:42:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-02 08:42:59 +0000 (Wed, 02 Mar 2022)");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_name("Mozilla Firefox Detection (Linux/Unix SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Mozilla Firefox.");

  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

files = ssh_find_file(file_name:"/firefox$", useregex:TRUE, sock:sock);

foreach file(files) {

  binary_name = chomp(file);
  if(!binary_name)
    continue;

  version = ssh_get_bin_version(full_prog_name:binary_name, sock:sock, version_argv:"-v", ver_pattern:"Mozilla Firefox ([0-9.]+([a-z0-9]+)?)");
  if(!isnull(version[1])) {

    set_kb_item(name:"Firefox/Linux/Ver", value:version[1]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);
    set_kb_item(name:"mozilla/firefox/linux/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/linux_macosx/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/linux_windows/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/windows_linux_macosx/detected", value:TRUE);

    cpe = build_cpe(value:version[1], exp:"^([0-9.a-z]+)", base:"cpe:/a:mozilla:firefox:");
    if(!cpe)
      cpe = "cpe:/a:mozilla:firefox";

    register_product(cpe:cpe, location:file, port:0, service:"ssh-login");

    log_message(data:build_detection_report(app:"Firefox",
                                            version:version[1],
                                            install:file,
                                            cpe:cpe,
                                            concluded:version[0]),
                port:0);
  }
}

ssh_close_connection();
exit(0);