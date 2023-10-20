# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803063");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-26 17:26:43 +0530 (Mon, 26 Nov 2012)");
  script_name("LibreOffice Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of LibreOffice.

  The script logs in via ssh, searches for folder 'LibreOffice.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
  line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
{
  exit(0);
}

if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

liboVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "LibreOffice.app/Contents/Info CFBundleGetInfoString"));
if(isnull(liboVer) || "does not exist" >< liboVer){
   exit(0);
}

liboVer = eregmatch(pattern:"LibreOffice ([0-9.]+).*(Build:([0-9.]+))?", string:liboVer);
if(!liboVer){
  exit(0);
}

if(liboVer[1] && liboVer[3])
  buildVer = liboVer[1] + "." + liboVer[3];

set_kb_item(name: "LibreOffice/MacOSX/Version", value: liboVer[1]);
set_kb_item( name:"LibreOffice/MacOSX/Installed", value:TRUE );

if(buildVer){
  set_kb_item(name: "LibreOffice-Build/MacOSX/Version", value: buildVer);
  set_kb_item( name:"LibreOffice/MacOSX/Installed", value:TRUE );
}


cpe = build_cpe(value:liboVer[1], exp:"^([0-9.]+)",
                   base:"cpe:/a:libreoffice:libreoffice:");
path = '/Applications/LibreOffice.app/';

if(isnull(cpe))
cpe = "cpe:/a:libreoffice:libreoffice";

register_product(cpe:cpe, location:path);

log_message(data: build_detection_report(app: "LibreOffice",
                                         version:liboVer[1],
                                         install:path,
                                         cpe:cpe,
                                         concluded: liboVer[1]));
