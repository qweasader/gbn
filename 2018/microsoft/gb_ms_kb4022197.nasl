# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813430");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-13 13:53:25 +0530 (Wed, 13 Jun 2018)");
  script_name("Microsoft SharePoint Server 2010 Service Pack 2 Word Automation Services Defense in Depth (KB4022197)");

  script_tag(name:"summary", value:"This host is missing a defense-in-depth update
  according to Microsoft KB4022197");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense in depth measure. This update
  improves the memory handling of Office applications that render Office Art.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass defense-in-depth measures and exploit Office applications that render
  Office Art.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2010 Service Pack 2 Word Automation Services.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4022197");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_server', exit_no_version:TRUE)) exit(0);
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(shareVer =~ "^(14\.)")
{
  dllVer = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\oartserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7210.4999"))
    {
      report = report_fixed_ver(file_checked:path + "\14.0\WebServices\WordServer\Core\oartserver.dll",
                                file_version:dllVer, vulnerable_range:"14.0 - 14.0.7210.4999");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);
