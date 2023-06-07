###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft OneNote Version Detection (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803436");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2013-03-13 11:28:48 +0530 (Wed, 13 Mar 2013)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft OneNote Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft OneNote.

The script logs in via smb, and detect the version of Microsoft OneNote
on remote host and sets the KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Office"))
{
  exit(0);
}

if("x86" >< osArch){
 exePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OneNote.exe", item:"Path");
}

else if("x64" >< osArch)
{
  exePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OneNote.exe", item:"Path");
  if(!exePath){
   exePath = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\OneNote.exe", item:"Path");
  }
}

if(exePath != NULL)
{
  noteVer = fetch_file_version(sysPath:exePath, file_name:"onenote.exe");

  if(noteVer)
  {
    set_kb_item(name:"MS/Office/OneNote/Ver", value:noteVer);

    cpe = build_cpe(value:noteVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:onenote:");
    if(isnull(cpe))
      cpe = 'cpe:/a:microsoft:onenote';

    if("x64" >< osArch && "Wow6432Node" >!< exePath)
    {
      set_kb_item(name:"MS/Office/OneNote64/Ver", value:noteVer);

      cpe = build_cpe(value:noteVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:onenote:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:microsoft:onenote:x64";
    }

    register_product(cpe:cpe, location:exePath);

    log_message(data: build_detection_report(app: "Microsoft OneNote",
                                             version: noteVer,
                                             install: exePath,
                                             cpe: cpe,
                                             concluded: noteVer));
  }
}
