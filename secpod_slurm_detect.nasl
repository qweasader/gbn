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
  script_oid("1.3.6.1.4.1.25623.1.0.900374");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SLURM Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of SLURM.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "SLURM Version Detection";

slurm_sock = ssh_login_or_reuse_connection();
if(!slurm_sock)
  exit(0);

paths = ssh_find_bin(prog_name:"slurmctld", sock:slurm_sock);
foreach binName (paths)
{

  binName = chomp(binName);
  if(!binName)
    continue;

  slurmVer = ssh_get_bin_version(full_prog_name:binName, sock:slurm_sock, version_argv:"-V", ver_pattern:"slurm ([0-9]\.[0-9.]+-?((rc)?[0-9]+)?)");
  if(slurmVer[1] != NULL)
  {
    slurmVer = ereg_replace(pattern:"-", replace:".", string:slurmVer[1]);
    if(slurmVer != NULL)
    {
      set_kb_item(name:"SLURM/Ver", value:slurmVer);
      log_message(data:"SLURM version " + slurmVer + " was detected on the host");
      ssh_close_connection();

      cpe = build_cpe(value:slurmVer, exp:"^([0-9.]+)", base:"cpe:/a:llnl:slurm:");
      if(!isnull(cpe))
        register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}

ssh_close_connection();
