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
  script_oid("1.3.6.1.4.1.25623.1.0.900598");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Novell Products Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves the installed
  version of Novell products.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");
include("list_array_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

eDirPath = ssh_find_bin(prog_name:"ndsd", sock:sock);
if(eDirPath) {

  edirPath = make_list_unique(edirPath, "/opt/novell/eDirectory/sbin/ndsd");

  foreach eDirFile(eDirPath) {

    eDirFile = chomp(eDirFile);
    if(!eDirFile) continue;

    eDirVer = ssh_get_bin_version(full_prog_name:eDirFile, version_argv:"--version", ver_pattern:"Novell eDirectory ([0-9.]+).?(SP[0-9]+)?", sock:sock);
    if(eDirVer[1]) {
      if(eDirVer[2]) {
        version = eDirVer[1] + "." + eDirVer[2];
      } else {
        version = eDirVer[1];
      }
      set_kb_item(name:"Novell/eDir/Lin/Ver", value:version);
      register_and_report_cpe(app:"Novell eDirectory version", ver:version, base:"cpe:/a:novell:edirectory:", expr:"^([0-9.]+([a-z0-9]+)?)", insloc:eDirFile, regService:"ssh-login", regPort:0, concluded:eDirVer[0]);
    }
  }
}

iPrintPaths = ssh_find_file(file_name:"/iprntcmd$", useregex:TRUE, sock:sock);
if(!iPrintPaths){
  ssh_close_connection();
  exit(0);
}

foreach iPrintBin(iPrintPaths) {

  iPrintBin = chomp(iPrintBin);
  if(!iPrintBin) continue;

  iPrintVer = ssh_get_bin_version(full_prog_name:iPrintBin, sock:sock, version_argv:"-v", ver_pattern:" v([0-9.]+)");
  if(iPrintVer[1]) {

    set_kb_item(name:"Novell/iPrint/Client/Linux/Ver", value:iPrintVer[1]);
    register_and_report_cpe(app:"Novell iPrint Client", ver:iPrintVer[1], base:"cpe:/a:novell:iprint_client:", expr:"^([0-9]\.[0-9]+)", insloc:iPrintBin, regService:"ssh-login", regPort:0, concluded:iPrintVer[0]);
  }
}

ssh_close_connection();
exit(0);
