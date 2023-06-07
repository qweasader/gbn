# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.818943");
  script_version("2022-01-24T03:04:40+0000");
  script_cve_id("CVE-2022-21911");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-01-24 03:04:40 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 18:53:00 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-12 09:31:05 +0530 (Wed, 12 Jan 2022)");
  script_name("Microsoft .NET Framework DoS Vulnerability (KB5009719)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5009719");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in .NET Framework which allows
  an unauthenticated attacker to cause a denial of service on an affected system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct a denial of service condition.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 for Microsoft Windows 7 SP1 and Microsoft Windows Server 2008 R2 SP1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5009719");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
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
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.web.dll");
          if(dllVer)
          {
            if(version_in_range(version:dllVer, test_version:"2.0.50727", test_version2:"2.0.50727.8954"))
            {
              vulnerable_range = "2.0.50727 - 2.0.50727.8954";
              break;
            }

            if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36719"))
            {
              vulnerable_range = "4.0.30319.30000 - 4.0.30319.36719";
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3904"))
            {
              vulnerable_range = "4.6 - 4.7.3904";
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4464"))
            {
              vulnerable_range = "4.8 - 4.8.4464";
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
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.web.dll");
        if(dllVer)
        {
          if(version_in_range(version:dllVer, test_version:"2.0.50727", test_version2:"2.0.50727.8954"))
          {
            vulnerable_range = "2.0.50727 - 2.0.50727.8954";
            break;
          }

          if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36719"))
          {
            vulnerable_range = "4.0.30319.30000 - 4.0.30319.36719";
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3904"))
          {
            vulnerable_range = "4.6 - 4.7.3904";
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4464"))
          {
            vulnerable_range = "4.8 - 4.8.4464";
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
      dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.web.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727", test_version2:"2.0.50727.8954"))
        {
          vulnerable_range = "2.0.50727 - 2.0.50727.8954";
          break;
        }

        if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36719"))
        {
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.36719";
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.6", test_version2:"4.7.3904"))
        {
          vulnerable_range = "4.6 - 4.7.3904";
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4464"))
        {
          vulnerable_range = "4.8 - 4.8.4464";
          break;
        }
      }
    }
  }

  if(vulnerable_range)
  {
    report = report_fixed_ver(file_checked:dotPath + "System.web.dll",
                              file_version:dllVer, vulnerable_range:vulnerable_range);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
