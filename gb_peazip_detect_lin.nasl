###############################################################################
# OpenVAS Vulnerability Test
#
# PeaZIP Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800594");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PeaZIP Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of PeaZIP.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

peazipName = ssh_find_file(file_name:"/peazip$", useregex:TRUE, sock:sock);
if(!peazipName) {
  ssh_close_connection();
  exit(0);
}

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("PeaZip [0-9.]\\+");

foreach binaryName(peazipName) {

  binaryName = chomp(binaryName);
  if(!binaryName)
    continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  peazipVer = ssh_get_bin_version(full_prog_name:"grep", version_argv:arg, sock:sock, ver_pattern:"([0-9.]{3,}[a-z]?)");
  if(peazipVer[1]){

    set_kb_item(name:"PeaZIP/Lin/Ver", value:peazipVer[1]);
    register_and_report_cpe(app:"PeaZIP", ver:peazipVer[1], base:"cpe:/a:giorgio_tani:peazip:", expr:"([0-9.]+)", regPort:0, insloc:binaryName, concluded:peazipVer[0], regService:"ssh-login");
    break;
  }
}

ssh_close_connection();
exit(0);
