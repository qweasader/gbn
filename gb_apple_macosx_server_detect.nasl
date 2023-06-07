###############################################################################
# OpenVAS Vulnerability Test
#
# Apple OS X Server Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810231");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-12-05 14:52:33 +0530 (Mon, 05 Dec 2016)");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Apple Mac OS X Server Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Apple Mac OS X Server.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

name = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Server.app/Contents/Info CFBundleName"));

if("Server" >< name) {
  serVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Server.app/Contents/Info CFBundleShortVersionString"));

  if(isnull(serVer) || "does not exist" >< serVer)
    serVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Server.app/Contents/version CFBundleShortVersionString"));

  close(sock);

  if(isnull(serVer) || "does not exist" >< serVer)
    exit(0);

  set_kb_item(name:"Apple/OSX/Server/Version", value:serVer);

  cpe = build_cpe(value:serVer, exp:"^([0-9.]+)", base:"cpe:/o:apple:os_x_server:");
  if(!cpe)
    cpe = "cpe:/o:apple:os_x_server";

  os_register_and_report(os:"Apple Mac OS X Server", cpe:cpe, desc:"Apple Mac OS X Server Detection (SSH Login)",
                         runs_key:"unixoide");

  register_product(cpe:cpe, location:"/Applications/Server.app", port:0, service:"ssh-login");

  log_message(data:build_detection_report(app:"Apple Mac OS X Server",
                                          version:serVer,
                                          install:"/Applications/Server.app/",
                                          cpe:cpe,
                                          concluded:serVer));
  exit(0);
}

exit(0);
