# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813726");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-24 15:06:45 +0530 (Tue, 24 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Oracle JRockit JVM Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of JRockit JVM.");

  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-jrockit-2192437.html");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\JRockit\Java Development Kit"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\JRockit\Java Development Kit")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\JRockit\Java Development Kit\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\JRockit\Java Development Kit\",
                        "SOFTWARE\Wow6432Node\JRockit\Java Development Kit\");
}

foreach rockitKey(key_list)
{
  keys = registry_enum_keys(key:rockitKey);
  foreach item(keys)
  {
    if(item =~ "([0-9._]+)-R([0-9.]+)-([0-9.]+)")
    {
      version = eregmatch(pattern:"([0-9._]+)-(R([0-9.]+))-([0-9.]+)", string:item);
      if(version){
        jrockitVer = version[2];
        jrockitjreVer = version[1];
        jrockitmcVer = version[4];
      }

      jrockitPath = registry_get_sz(item:"JavaHome", key:rockitKey + item);
      jrockitloc = eregmatch(pattern:"(.*)\jrockit.*", string:jrockitPath);
      jrockitPath = jrockitloc[1];
      if(jrockitVer)
      {
        set_kb_item(name:"JRockit/Win/Installed", value:TRUE);
        set_kb_item(name:"JRockit/Win/Ver", value:jrockitVer);
        set_kb_item(name:"JRockit/Jre/Win/Ver", value:jrockitjreVer);
        set_kb_item(name:"JRockit/MC/Win/Ver", value:jrockitmcVer);

        register_and_report_cpe(app:"JRockit JVM", ver:jrockitVer, base:"cpe:/a:oracle:jrockit:",
                                expr:"^(R[0-9.]+)", insloc:jrockitPath);

        if("64" >< os_arch && "Wow6432Node" >!< rockitKey)
        {
          set_kb_item(name:"JRockit64/Win/Installed", value:TRUE);
          set_kb_item(name:"JRockit64/Win/Ver", value:jrockitVer);
          set_kb_item(name:"JRockit64/Jre/Win/Ver", value:jrockitjreVer);
          set_kb_item(name:"JRockit64/MC/Win/Ver", value:jrockitmcVer);

          register_and_report_cpe(app:"JRockit JVM", ver:jrockitVer, base:"cpe:/a:oracle:jrockit:x64:",
                                  expr:"^(R[0-9.]+)", insloc:jrockitPath);
        }
        exit(0);
      }
    }
  }
}

exit(0);