###############################################################################
# OpenVAS Vulnerability Test
#
# libESMTP Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800496");
  script_version("2020-03-27T14:05:33+0000");
  script_tag(name:"last_modification", value:"2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("libESMTP Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of libESMTP.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"libesmtp-config", sock:sock);
foreach bin(paths) {

  bin = chomp(bin);
  if(!bin)
    continue;

  libesmtpVer = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"--version", ver_pattern:"(([0-9.]+).?([a-zA-Z0-9]+)?)");
  if(!libesmtpVer[1])
    continue;

  version = ereg_replace(pattern:" |-", string:libesmtpVer[1], replace:".");
  if(!version || version !~ "^[0-9.]{5,}")
    continue;

  set_kb_item(name:"libesmtp/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:stafford.uklinux:libesmtp:");
  if(!cpe)
    cpe = "cpe:/a:stafford.uklinux:libesmtp";

  register_product(cpe:cpe, location:bin, service:"ssh-login");
  log_message(data:build_detection_report(app:"libESMTP",
                                          version:version,
                                          install:bin,
                                          cpe:cpe,
                                          concluded:libesmtpVer[0]));
}

ssh_close_connection();
exit(0);
