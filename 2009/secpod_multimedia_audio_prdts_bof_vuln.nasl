# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900458");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0476");
  script_name("MultiMedia Soft Audio Products Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33589");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7973");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"affected", value:"The following components with AdjMmsEng.dll file version 7.11.2.7 and prior.

  MultiMedia Soft Audio DJ Studio for .NET

  MultiMedia Soft Audio Sound Recorder for .NET

  MultiMedia Soft Audio Sound Editor for .NET");

  script_tag(name:"insight", value:"The vulnerability exists in AdjMmsEng.dll file of multiple MultiMedia Soft
  audio components for .NET. This issue arises due to failure in performing
  adequate boundary checks on user supplied input to the application buffer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest versions.");

  script_tag(name:"summary", value:"MultiMedia Soft Audio Products is prone to a buffer overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application through crafted playlist files 'file.pls' with
  overly long data which may lead to crashing of the application.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\";
if(!registry_key_exists(key:key))exit(0);

foreach item(registry_enum_keys(key:key))
{
  if(item =~ "(MMS.AudioDjStudio|MMS.AudioSoundEditor|MMS.AudioSoundRecorder)")
  {
    djPath = registry_get_sz(key:key + item, item:"InstPath");
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:djPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:djPath +
                        "\Redist\AdjMmsEng.dll");
    version = GetVer(file:file, share:share);
    if(version != NULL)
    {
      if(version_is_less_equal(version:version, test_version:"7.11.2.7"))
      {
        report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 7.11.2.7", install_path:djPath);
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
