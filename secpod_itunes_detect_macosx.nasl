# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902717");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_name("Apple iTunes Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"This script finds the installed product version of Apple iTunes
on Mac OS X");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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
