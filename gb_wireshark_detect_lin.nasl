###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800039");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Wireshark Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Wireshark.

The script logs in via ssh, searches for executable 'wireshark' and
queries the found executables via command line option '-v'.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

wiresharkName = ssh_find_file(file_name:"/wireshark$", useregex:TRUE, sock:sock);
foreach executableFile (wiresharkName)
{
  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  sharkVer = ssh_get_bin_version(full_prog_name:executableFile, version_argv:"-v", ver_pattern:"[Ww]ireshark ([0-9.]+)", sock:sock);
  if(sharkVer)
  {
    set_kb_item(name:"Wireshark/Linux/Ver", value:sharkVer[1]);

    cpe = build_cpe(value:sharkVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile);

    log_message(data:'Detected Wireshark version: ' + sharkVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + sharkVer[max_index(sharkVer)-1]);
  }
}

ssh_close_connection();

exit( 0 );
