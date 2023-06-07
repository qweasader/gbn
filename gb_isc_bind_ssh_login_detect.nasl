# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145293");
  script_version("2021-02-12T12:40:45+0000");
  script_tag(name:"last_modification", value:"2021-02-12 12:40:45 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-02 03:41:46 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("ISC BIND Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of ISC BIND.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

soc = ssh_login_or_reuse_connection();
if (!soc)
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_bin(prog_name: "named", sock: soc);

foreach bin (paths) {
  bin = chomp(bin);
  if (!bin)
    continue;

  # BIND 9.11.4-P2-9.11.4-17.h2.eulerosv2r9 (Extended Support Version) <id:7107deb>
  # BIND 9.16.1-Ubuntu (Stable Release) <id:d497c32>
  # BIND 9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.3 (Extended Support Version) <id:7107deb>
  # BIND 9.16.6 (Stable Release) <id:25846cf>
  vers = ssh_get_bin_version(full_prog_name: bin, sock: soc, version_argv: "-v", ver_pattern: "BIND ([0-9.]{3,})(-ESV-?|-)?((rc|RC|P|R|W|S|a|b|beta)[0-9]+)?(-?(rc|RC|P|R|W|S|a|b|beta)[0-9]+)?(.*)");
  if (isnull(vers[1]))
    continue;

  if (!isnull(vers[3])) {
    update = vers[3];
    if (!isnull(vers[5]))
      update += vers[5];
  }

  set_kb_item(name: "isc/bind/detected", value: TRUE);
  set_kb_item(name: "isc/bind/ssh-login/detected", value: TRUE);
  set_kb_item(name: "isc/bind/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + vers[1] + "#---#" + update + "#---#tcp#---#" + vers[0]);
}

exit(0);
