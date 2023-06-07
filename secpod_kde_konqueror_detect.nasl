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
  script_oid("1.3.6.1.4.1.25623.1.0.900902");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("KDE Konqueror Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of KDE Konqueror.

  The script logs in via ssh, searches for executable 'konqueror' and
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

konqerName = ssh_find_file(file_name:"/konqueror$", useregex:TRUE, sock:sock);
foreach executableFile (konqerName)
{
  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  # Returns e.g.
  # Qt: 4.8.6
  # KDE Development Platform: 4.14.25
  # Konqueror: 4.14.25
  konqerVer = ssh_get_bin_version(full_prog_name:executableFile, version_argv:"-v", ver_pattern:"Konqueror: ([0-9.]+).?((rc|RC)?[0-9]+)?", sock:sock);
  if(konqerVer[0]) {

    _konqerVer = eregmatch( string:konqerVer[0], pattern:"Konqueror: ([0-9.]+).?((rc|RC)?[0-9]+)?");

    if(!isnull(_konqerVer[2]))
      ver = _konqerVer[1] + "." + _konqerVer[2];
    else
      ver = _konqerVer[1];

    set_kb_item(name:"KDE/Konqueror/Ver", value:ver);
    set_kb_item(name:"kde/konqueror/detected", value:TRUE);

    register_and_report_cpe(app:"KDE Konqueror", ver:ver, base:"cpe:/a:kde:konqueror:", expr:"([0-9.]+)", regPort:0, insloc:executableFile, concluded:konqerVer[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
