###############################################################################
# OpenVAS Vulnerability Test
#
# AIMP Detection (Windows SMB Login)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800590");
  script_version("2021-01-15T07:13:31+0000");
  script_tag(name:"last_modification", value:"2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AIMP2 Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of AIMP2 player.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AIMP2";
appName = registry_get_sz(key:key, item:"DisplayName");

if("AIMP2" >< appName) {

  vers = "unknown";
  path = "unknown";

  aimpPath = registry_get_sz(key:key, item:"UninstallString");
  if(aimpPath) {
    share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:aimpPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:aimpPath - "\UnInstall.exe" - "Uninstall.exe" + "\AIMP2.exe");
    path = file;
    aimpVer = GetVer(share:share, file:file);
    if(aimpVer) {
      set_kb_item(name:"AIMP/Ver", value:aimpVer);
      vers = aimpVer;
    }
  }

  cpe = build_cpe(value:vers, exp:"^[0-9.]+([a-z0-9]+)?)", base:"cpe:/a:aimp:aimp2_audio_converter:");
  if(!cpe)
    cpe = "cpe:/a:aimp:aimp2_audio_converter";

  register_product(cpe:cpe, location:path, port:0, service:"smb-login");

  log_message(data:build_detection_report(app:"AIMP2",
                                          version:vers,
                                          install:path,
                                          cpe:cpe,
                                          concluded:aimpVer));

}

exit(0);
