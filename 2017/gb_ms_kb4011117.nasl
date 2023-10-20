# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811668");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8745");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 16:04:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 09:20:23 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft SharePoint Foundation 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4011117)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011117");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Microsoft SharePoint
  Server does not properly sanitize a specially crafted web request to an
  affected SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to perform cross-site scripting attacks on affected systems and
  run script in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Foundation 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011117");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100753");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Foundation/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_foundation', exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(shareVer =~ "^(15\.)")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    ## Installation Path
    path = path + "\microsoft shared\Web Server Extensions\15\BIN";

    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4963.0999"))
      {
        report = 'File checked:     ' +  path + "\Onetutil.dll"+ '\n' +
                 'File version:     ' +  dllVer  + '\n' +
                 'Vulnerable range: ' +  "15.0 - 15.0.4963.0999" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

exit(99);
