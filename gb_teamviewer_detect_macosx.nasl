# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813896");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2018-09-07 13:42:31 +0530 (Fri, 07 Sep 2018)");
  script_name("TeamViewer Version Detection (Mac OS X)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  script_xref(name:"URL", value:"https://www.teamviewer.com/en");

  script_tag(name:"summary", value:"Detects the installed version of
  TeamViewer on Mac OS X.

  The script logs in via ssh, searches for folder 'TeamViewer.app' and queries the
  related 'info.plist' file for string 'CFBundleShortVersionString' via command line
  option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

teamVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                                         "TeamViewer.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(teamVer) || "does not exist" >< teamVer){
  exit(0);
}

set_kb_item(name:"TeamViewer/MacOSX/Version", value:teamVer);

cpe = build_cpe(value:teamVer, exp:"^([0-9.]+)", base:"cpe:/a:teamviewer:teamviewer:");
if(isnull(cpe))
  cpe = 'cpe:/a:teamviewer:teamviewer';

register_product(cpe:cpe, location:'/Applications/TeamViewer.app');

log_message(data:build_detection_report(app:"TeamViewer",
                                        version:teamVer,
                                        install:"/Applications/TeamViewer.app",
                                        cpe:cpe,
                                        concluded:teamVer));
exit(0);
