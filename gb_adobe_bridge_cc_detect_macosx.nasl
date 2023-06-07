# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815247");
  script_version("2021-03-01T04:08:26+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-03-01 04:08:26 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"creation_date", value:"2019-07-12 08:34:59 +0530 (Fri, 12 Jul 2019)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Bridge CC Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Bridge CC.

  The script logs in via ssh, searches for folder 'Adobe Bridge CC'
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

foreach ver (make_list("2015", "2017", "2018", "2019", "2020", "2021")) {

  AppVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                                          "Adobe\ Bridge\ CC\ " + ver + "/Adobe\ Bridge\ " + ver + ".app/Contents/Info CFBundleShortVersionString"));

  if(isnull(AppVer) || "does not exist" >< AppVer) {
    continue;
  }

  if(AppVer) {
    app = 'Adobe Bridge CC';
    application = app + " " + ver;
    set_kb_item(name:"Adobe/Bridge/CC/MacOSX/Version", value:AppVer);

    path = '/Applications/' + application;
    register_and_report_cpe(app:application,
                            ver:AppVer,
                            base:"cpe:/a:adobe:bridge_cc:",
                            expr:"^([0-9.]+)",
                            insloc:path,
                            concluded:AppVer);
  }
}

close(sock);

exit(0);
