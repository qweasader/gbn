##############################################################################
# OpenVAS Vulnerability Test
#
# Google SketchUp Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800434");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google SketchUp Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Google SketchUp.

The script logs in via smb, searches for Google SketchUp in the registry
and gets the version from registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Google") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Google")){
  exit(0);
}

if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    gsName = registry_get_sz(key:key + item, item:"DisplayName");
    if(gsName =~ "(Google )?SketchUp")
    {
      path = registry_get_sz(key:key + item , item:"InstallLocation");
      if(path)
      {
        gsVer = fetch_file_version(sysPath:path, file_name:"SketchUp.exe");
        if(gsVer != NULL)
        {
          set_kb_item(name:"Google/SketchUp/Win/Ver", value:gsVer);

          cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:google:sketchup:");
          if(isnull(cpe))
            cpe = 'cpe:/a:google:sketchup';

          if("x64" >< osArch && "Wow6432Node" >!< key)
          {
            set_kb_item(name:"Google/SketchUp64/Win/Ver", value:gsVer);

            cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:google:sketchup:x64:");
            if(isnull(cpe))
              cpe = 'cpe:/a:google:sketchup:x64';
          }

          register_product(cpe:cpe, location:path);
          log_message(data: build_detection_report(app: "Google SketchUp",
                                                   version: gsVer,
                                                   install: path,
                                                   cpe: cpe,
                                                   concluded: gsVer));

          ## To improve performance by avoiding extra iteration over uninstall path
          exit(0);
        }
      }
    }
  }
}
