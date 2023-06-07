##############################################################################
# OpenVAS Vulnerability Test
#
# Flock Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800878");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Flock Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of the Flock Browser.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Flock Detection (Linux)";

f_soc = ssh_login_or_reuse_connection();
if(!f_soc)
  exit(0);

foreach item (make_list("flock-browser", "flock"))
{
  flock_paths = ssh_find_file(file_name:"/" + item + "$", useregex:TRUE, sock:f_soc);
  if(!isnull(flock_paths))
  {
    foreach binaryName (flock_paths)
    {

      binaryName = chomp(binaryName);
      if(!binaryName)
        continue;

      flockVer = ssh_get_bin_version(full_prog_name:binaryName, sock:f_soc, version_argv:"--version", ver_pattern:"Flock Browser ([0-9]\.[0-9.]+((b|rc)[0-9])?)");
      if(!isnull(flockVer[1]))
      {
        set_kb_item(name:"Flock/Linux/Ver", value:flockVer[1]);
        log_message(data:"Flock Browser version " + flockVer[1] + " was detected on the host");

        cpe = build_cpe(value:flockVer[1], exp:"^([0-9.]+)", base:"cpe:/a:flock:flock:");
        if(!isnull(cpe))
          register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
      }
    }
  }
}
ssh_close_connection();
