# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900675");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mutt Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Mutt.

  The script logs in via ssh, searches for executable 'mutt' and
  queries the found executables via command line option '-v'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"mutt", sock:sock);
foreach executableFile (paths) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  muttVer = ssh_get_bin_version(full_prog_name:executableFile, sock:sock, version_argv:"-v", ver_pattern:"Mutt (([0-9.]+)([a-z])?)");
  if(!isnull(muttVer[1])) {

    set_kb_item(name:"Mutt/Ver", value:muttVer[1]);
    set_kb_item(name:"mutt/detected", value:TRUE);

    # nb: Don't use muttVer[max_index(muttVer)-1]) for the concluded string because the output is quite huge (around 60 lines)...
    register_and_report_cpe( app:"Mutt", ver:muttVer[1], concluded:muttVer[0], base:"cpe:/a:mutt:mutt:", expr:"^([0-9.]+)", insloc:executableFile, regPort:0, regService:"ssh-login" );
  }
}

ssh_close_connection();
exit(0);
