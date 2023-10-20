# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811230");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8569");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-12 11:58:37 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft SharePoint Enterprise Server 2016 Elevation of Privilege Vulnerability (KB3213544)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3213544");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error when
  Microsoft SharePoint Server does not properly sanitize a specially
  crafted web request to an affected SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to perform cross-site scripting attacks on affected systems and run script in
  the security context of the current user. These attacks could allow the attacker
  to read content that the attacker is not authorized to read, use the victim's
  identity to take actions on the SharePoint site on behalf of the user, such as
  change permissions and delete content, and inject malicious content in the
  browser of the user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Enterprise Server 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99447");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_server', exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(shareVer =~ "^16\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\16\BIN";

    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");

    if(dllVer && version_in_range(version:dllVer, test_version:"16.0", test_version2:"16.0.4561.0999"))
    {
      report = 'File checked:     ' +  path + "\Onetutil.dll"+ '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: 16.0 - 16.0.4561.0999' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
