# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815040");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-04-18 17:01:02 +0530 (Thu, 18 Apr 2019)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Dreamweaver Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Dreamweaver on Mac OS X.

  The script logs in via ssh, searches for folder 'Adobe Dreamweaver.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
  line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
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

foreach ver (make_list("", "3", "4", "5", "5.5", "6"))
{
  dreamVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Adobe\ Dreamweaver\ CS" + ver +"/Adobe\ Dreamweaver.app/" +
             "Contents/Info CFBundleVersion"));
  if(isnull(dreamVer)|| "does not exist" >< dreamVer){
    continue;
  }

  install = TRUE ;
  version = dreamVer ;
  app = 'Adobe Dreamweaver CS';
  application = app + " " + ver ;
}

if(!install)
{
  foreach ver (make_list("2014", "2015", "2017", "2018", "2019"))
  {
    dreamVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "Adobe\ Dreamweaver\ CC\ " + ver + "/Adobe\ Dreamweaver\ " + ver + ".app/" +
               "Contents/Info CFBundleVersion"));

    if(isnull(dreamVer)|| "does not exist" >< dreamVer){
      continue;
    }

    install = TRUE ;
    version = dreamVer ;
    app = 'Adobe Dreamweaver CC';
    application = app + " " + ver ;
  }
}

close(sock);

if(install && version)
{
  set_kb_item(name: "Adobe/Dreamweaver/MacOSX/Version", value:version);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:dreamweaver:");
  if(isnull(cpe)){
    cpe = 'cpe:/a:adobe:dreamweaver';
  }

  path = '/Applications/' + application;

  register_and_report_cpe(app:application,
                            ver:version,
                            base:"cpe:/a:adobe:dreamweaver:",
                            expr:"^([0-9.]+)",
                            insloc:path,
                            concluded:version);
  exit(0);
}
exit(99);
