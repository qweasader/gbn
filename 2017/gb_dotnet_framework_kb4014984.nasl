# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810868");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0160");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-13 11:30:09 +0530 (Thu, 13 Apr 2017)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (KB4014984)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates KB4014984");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as .NET Framework fails to properly
  validate input before loading libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to take control of an affected system.");

  script_tag(name:"affected", value:"- Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 4.5.2

  - Microsoft .NET Framework 4.6");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4014984");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3,
                   win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  dotPath = registry_get_sz(key:key + item, item:"Path");
  if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
  {
    ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
    ## https://support.microsoft.com/en-us/kb/4014561
    if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
    {
      sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"System.data.dll");
      if(sysdllVer)
      {
        if(version_in_range(version:sysdllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8750"))
        {
          report = 'File checked:     ' + dotPath + "\System.data.dll" + '\n' +
                   'File version:     ' + sysdllVer  + '\n' +
                   'Vulnerable range:  2.0.50727.5700 - 2.0.50727.8750\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }

    ## Extracted and Verified file is updating
    sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"system.management.dll");
    if(sysdllVer)
    {
      ## .NET Framework 4.5.2 on Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      ## https://support.microsoft.com/en-us/help/4014559
      if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3, win7:2, win7x64:2, win2008r2:2) > 0)
      {
        if(version_in_range(version:sysdllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36387"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.0.30319.30000 - 4.0.30319.36387";
        }

        ## .NET Framework 4.6 for Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1,
        ## and Windows Server 2008 R2 SP1 and the .NET Framework 4.6.1 for Windows 7 SP1 and
        else if(version_in_range(version:sysdllVer, test_version:"4.6", test_version2:"4.6.1097"))
        {
          VULN = TRUE ;
          vulnerable_range = "4.6 - 4.6.1097";
        }

        if(VULN)
        {
          report = 'File checked:     ' + dotPath + "\system.management.dll" + '\n' +
                   'File version:     ' + sysdllVer  + '\n' +
                   'Vulnerable range: ' + vulnerable_range + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
