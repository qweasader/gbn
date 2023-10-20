# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800120");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Google Chrome Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Google Chrome.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if(appName == "Google Chrome")
  {
    chromeVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(chromeVer)
    {
      chromePath = registry_get_sz(key:key + item, item:"InstallLocation");

      set_kb_item(name:"GoogleChrome/Win/Ver", value:chromeVer);
      set_kb_item(name:"google/chrome/detected", value:TRUE);

      cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
      if(!cpe)
        cpe = "cpe:/a:google:chrome";

      # nb: Used in gb_google_chrome_detect_portable_win.nasl to detect doubled detections
      set_kb_item(name:"GoogleChrome/Win/InstallLocations", value:tolower(chromePath));

      register_product(cpe:cpe, location:chromePath, port:0, service:"smb-login");
      log_message(data:build_detection_report(app:"Google Chrome",
                                              version:chromeVer,
                                              install:chromePath,
                                              cpe:cpe,
                                              concluded:chromeVer),
                  port:0);
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\";
if(!registry_key_exists(key:key)){
  exit(0);
}

enumKeys = registry_enum_keys(key:key);

foreach key (enumKeys)
{
  chromeVer = registry_get_sz(key:key + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome", item:"Version", type:"HKU");
  if(chromeVer)
  {
    chromePath = registry_get_sz(key:key + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome", item:"InstallLocation", type:"HKU");

    set_kb_item(name:"GoogleChrome/Win/Ver", value:chromeVer);
    set_kb_item(name:"google/chrome/detected", value:TRUE);

    cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
    if(!cpe)
     cpe = "cpe:/a:google:chrome";

    # Used in gb_google_chrome_detect_portable_win.nasl to detect doubled detections
    set_kb_item(name:"GoogleChrome/Win/InstallLocations", value:tolower(chromePath));

    register_product(cpe:cpe, location:chromePath, port:0, service:"smb-login");
    log_message(data:build_detection_report(app:"Google Chrome",
                                            version:chromeVer,
                                            install:chromePath,
                                            cpe:cpe,
                                            concluded:chromeVer),
                port:0);
  }
}

exit(0);
