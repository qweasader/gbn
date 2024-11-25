# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900003");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Apple Safari Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Apple Safari on Windows.

The script logs in via smb, searches for Apple Safari in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Apple Computer, Inc.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  safariName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Safari" >< safariName)
  {
    safariPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(safariPath)
    {
      safariVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(safariVer)
      {
        set_kb_item(name:"AppleSafari/Version", value:safariVer);

        cpe = build_cpe(value:safariVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:safari:");
        if(isnull(cpe))
          cpe="cpe:/a:apple:safari";

        register_product(cpe: cpe, location: safariPath);

        log_message(data: build_detection_report(app: safariName,
                                              version: safariVer,
                                             install: safariPath,
                                             cpe: cpe,
                                             concluded: safariVer));
      }
    }
  }
}
