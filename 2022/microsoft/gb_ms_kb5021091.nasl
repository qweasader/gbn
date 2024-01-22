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
  script_oid("1.3.6.1.4.1.25623.1.0.826730");
  script_version("2023-11-21T05:05:52+0000");
  script_cve_id("CVE-2022-41089");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 17:39:00 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-12-14 09:40:30 +0530 (Wed, 14 Dec 2022)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (KB5021091)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5021091");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient validation
  of user-supplied input in the .NET Framework.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5.1, 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 for Microsoft Windows 7 SP1 and Microsoft Windows Server 2008 R2 SP1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5021091");

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
      NetPath = registry_get_sz(key:key, item:"InstallRoot");
      if(NetPath && "\Microsoft.NET\Framework" >< NetPath)
      {
        foreach item (registry_enum_keys(key:key))
        {
          dotPath = NetPath + item;
          dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
          dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

          if(dllVer1 || dllVer2)
          {
            if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8952"))
            {
              VULN1 = TRUE ;
              vulnerable_range1 = "3.0.6920.8600 - 3.0.6920.8952";
              break;
            }
            else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.7", test_version2:"4.7.4009"))
            {
              VULN2 = TRUE ;
              vulnerable_range2 = "4.7 - 4.7.4009" ;
              break;
            }

            else if(version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4589"))
            {
              VULN2 = TRUE ;
              vulnerable_range2 = "4.8 - 4.8.4589" ;
              break;
            }
          }
        }
        if(vulnerable_range1 || vulnerable_range2){
          break;
        }
      }
    }

  }

  if((!vulnerable_range1 || !vulnerable_range2) && "ASP.NET" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      dotPath = registry_get_sz(key:key, item:"Path");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
        dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

        if(dllVer1 || dllVer2)
        {
          if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8952"))
          {
            VULN1 = TRUE ;
            vulnerable_range1 = "3.0.6920.8600 - 3.0.6920.8952";
            break;
          }
          else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.7", test_version2:"4.7.4009"))
          {
            VULN2 = TRUE ;
            vulnerable_range2 = "4.7 - 4.7.4009" ;
            break;
          }

          else if(version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4589"))
          {
            VULN2 = TRUE ;
            vulnerable_range2 = "4.8 - 4.8.4589" ;
            break;
          }
        }
      }
    }
  }

  ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
  if((!vulnerable_range1 || !vulnerable_range2) && "NET Framework Setup" >< key)
  {
    dotPath = registry_get_sz(key:key, item:"InstallPath");
    if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
    {
      dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
      dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

      if(dllVer1 || dllVer2)
      {
        if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8952"))
        {
          VULN1 = TRUE ;
          vulnerable_range1 = "3.0.6920.8600 - 3.0.6920.8952";
          break;
        }
        else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.7", test_version2:"4.7.4009"))
        {
          VULN2 = TRUE ;
          vulnerable_range2 = "4.7 - 4.7.4009" ;
          break;
        }

        else if(version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4589"))
        {
          VULN2 = TRUE ;
          vulnerable_range2 = "4.8 - 4.8.4589" ;
          break;
        }
      }
    }
  }

  if(VULN1)
  {
    report = report_fixed_ver(file_checked:dotPath + "\System.printing.dll",
                              file_version:dllVer2, vulnerable_range:vulnerable_range1);
    security_message(data:report);
    exit(0);
  }

  if(VULN2)
  {
    report = report_fixed_ver(file_checked:dotPath + "\System.core.dll",
                                file_version:dllVer1, vulnerable_range:vulnerable_range2);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
