###############################################################################
# OpenVAS Vulnerability Test
#
# 7zip Version Detection (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800255");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("7zip Version Detection (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of 7zip.

  The script logs in via ssh, searches for executable '7za' and
  queries the found executables via command line option 'invalidcmd'.
  The error message output of 7za is normal because 7za in fact
  offers no version command and thus an invalid command has to be
  passed to obtain the version number.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/7za$", useregex:TRUE, sock:sock);
foreach executableFile (paths)
{
  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  zipVer = ssh_get_bin_version(full_prog_name:executableFile, sock:sock, version_argv:"invalidcmd", ver_pattern:"p7zip Version ([0-9]\.[0-9][0-9]?)");
  if(zipVer[1] != NULL)
  {
    set_kb_item(name:"7zip/Lin/Ver", value:zipVer[1]);

    cpe = build_cpe(value: zipVer[1], exp:"^([0-9.]+)",base:"cpe:/a:7-zip:7-zip:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile);

    log_message(data:'Detected 7zip version: ' + zipVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + zipVer[max_index(zipVer)-1]);
  }
}

ssh_close_connection();
