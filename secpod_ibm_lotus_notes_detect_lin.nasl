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
  script_oid("1.3.6.1.4.1.25623.1.0.901016");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Lotus Notes Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of IBM Lotus Notes item.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "IBM Lotus Notes Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/nsd\.sh$", useregex:TRUE, sock:sock);

foreach binName (paths)
{

  binName = chomp(binName);
  if(!binName)
    continue;

  lotusVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName, ver_pattern:'SCR_VERSION="([0-9.]+)', sock:sock);

  if(lotusVer[1] != NULL){
    set_kb_item(name:"IBM/LotusNotes/Linux/Ver", value:lotusVer[1]);
    log_message(data:"IBM Lotus Notes version " + lotusVer[1] + " running at location " + binName + " was detected on the host");

    cpe = build_cpe(value:lotusVer[1], exp:"^([0-9]\.[0-9]+\.[0-9]+)", base:"cpe:/a:ibm:lotus_notes:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
