# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:project_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810788");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0281");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-10 14:16:40 +0530 (Wed, 10 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Project Server Remote Code Execution Vulnerability (KB3191890)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3191890");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in Microsoft Office software
  when the software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user on an
  affected system.");

  script_tag(name:"affected", value:"Microsoft Project Server 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3191890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98101");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_project_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/ProjectServer/Server/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

psVer = get_app_version(cpe:CPE);
if(!psVer){
  exit(0);
}

## Microsoft Project Server 2013
if(psVer =~ "^15\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\Microsoft Shared\web server extensions\15\CONFIG\BIN";

    dllVer = fetch_file_version(sysPath:path,
             file_name:"Microsoft.office.project.server.pwa.applicationpages.dll");

    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4919.0999"))
      {
        report = 'File checked:     ' + path + "\Microsoft.office.project.server.pwa.applicationpages.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: ' + "15.0 - 15.0.4919.0999" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

exit(99);
