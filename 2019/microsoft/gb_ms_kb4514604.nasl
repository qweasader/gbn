# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815607");
  script_version("2021-09-06T12:01:32+0000");
  script_cve_id("CVE-2019-1142");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-09-11 08:59:02 +0530 (Wed, 11 Sep 2019)");
  script_name("Microsoft .NET Framework Privilege Escalation Vulnerability (KB4514604)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4514604");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as .NET Framework common
  language runtime (CLR) allows file creation in arbitrary locations.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to write files to folders that require higher privileges than what the attacker
  already has.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5, 4.5.2, 4.6, 4.6.1, 4.6.2, 4.7, 4.7.1, 4.7.2 and 4.8 for Microsoft Windows 8.1 and Microsoft Windows Server 2012 R2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4514604");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4514371");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4514367");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4514364");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4514361");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")){
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")){
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")){
      exit(0);
    }
  }
}

key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

foreach key(key_list)
{
  if(".NETFramework" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      NetPath = registry_get_sz(key:key + item, item:"InstallRoot");
      if(NetPath && "\Microsoft.NET\Framework" >< NetPath)
      {
        foreach item (registry_enum_keys(key:key))
        {
          dotPath = NetPath + item;
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"mscorlib.dll");
          if(dllVer)
          {
            ## https://support.microsoft.com/en-us/help/4514371
            if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8809"))
            {
              vulnerable_range = "2.0.50727.5700 - 2.0.50727.8809";
              break;
            }
            ## https://support.microsoft.com/en-us/help/4514367
            else if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36574"))
            {
              vulnerable_range = "4.0.30319.30000 - 4.0.30319.36574";
              break;
            }
            # https://support.microsoft.com/en-us/help/4514364
            else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3459"))
            {
              vulnerable_range = "4.6 - 4.7.3459";
              break;
            }
            ## https://support.microsoft.com/en-us/help/4514361
            else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4009"))
            {
              vulnerable_range = "4.8 - 4.8.4009";
              break;
            }
          }
        }
        if(vulnerable_range){
          break;
        }
      }
    }
  }

  if((!vulnerable_range) && "ASP.NET" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      dotPath = registry_get_sz(key:key + item, item:"Path");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"mscorlib.dll");
        if(dllVer)
        {
          ## https://support.microsoft.com/en-us/help/4514371
          if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8809"))
          {
            vulnerable_range = "2.0.50727.5700 - 2.0.50727.8809";
            break;
          }
          ## https://support.microsoft.com/en-us/help/4514367
          else if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36574"))
          {
            vulnerable_range = "4.0.30319.30000 - 4.0.30319.36574";
            break;
          }
          # https://support.microsoft.com/en-us/help/4514364
          else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3459"))
          {
            vulnerable_range = "4.6 - 4.7.3459";
            break;
          }
          ## https://support.microsoft.com/en-us/help/4514361
          else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4009"))
          {
            vulnerable_range = "4.8 - 4.8.4009";
            break;
          }
        }
      }
    }
  }

  ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)

  if((!vulnerable_range) && "NET Framework Setup" >< key)
  {
    dotPath = registry_get_sz(key:key, item:"InstallPath");
    if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
    {
      dllVer = fetch_file_version(sysPath:dotPath, file_name:"mscorlib.dll");
      if(dllVer)
      {
        ## https://support.microsoft.com/en-us/help/4514371
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8809")){
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.8809";
        }
        ## https://support.microsoft.com/en-us/help/4514367
        else if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36574")){
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.36574";
        }
        # https://support.microsoft.com/en-us/help/4514364
        else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3459")){
          vulnerable_range = "4.6 - 4.7.3459";
        }
        ## https://support.microsoft.com/en-us/help/4514361
        else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4009")){
          vulnerable_range = "4.8 - 4.8.4009";
        }
      }
    }
  }

  if(vulnerable_range)
  {
    report = report_fixed_ver(file_checked:dotPath + "mscorlib.dll",
                              file_version:dllVer, vulnerable_range:vulnerable_range);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
