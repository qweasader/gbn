# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902717");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_name("Apple iTunes Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"This script finds the installed product version of Apple iTunes
on Mac OS X");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if(!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

itunesVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                  "iTunes.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(itunesVer) || "does not exist" >< itunesVer){
  exit(0);
}

set_kb_item(name: "Apple/iTunes/MacOSX/Version", value:itunesVer);


cpe = build_cpe(value:itunesVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:itunes:");
if(isnull(cpe))
  cpe = 'cpe:/a:apple:itunes';

insPath = "/Applications/iTunes.app";

register_product(cpe:cpe, location:insPath);

log_message(data: build_detection_report(app: "Apple iTunes",
                                         version: itunesVer,
                                         install: insPath,
                                         cpe: cpe,
                                         concluded: itunesVer));
