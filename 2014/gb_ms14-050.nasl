# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804741");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-2816");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-08-13 17:07:01 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft SharePoint Server and Foundation Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS14-050.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is triggered when handling custom actions in a specially crafted
  application.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain elevated privileges.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2013

  - Microsoft SharePoint Foundation 2013");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2880994");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69099");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-050");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server_or_Foundation_or_Services/Installed");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cpe_list = make_list("cpe:/a:microsoft:sharepoint_server", "cpe:/a:microsoft:sharepoint_foundation");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# nb: SharePoint Server and Foundation 2013
if(vers =~ "^15\.") {
  check_path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(check_path) {
    check_path += "\microsoft shared\SERVER15\Server Setup Controller";
    check_file = "Wsssetup.dll";

    dllVer = fetch_file_version(sysPath:check_path, file_name:check_file);
    if(dllVer) {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4641.999")) {
        report = report_fixed_ver(file_checked:check_path + "\" + check_file, installed_version:dllVer, vulnerable_range:"15.0 - 15.0.4641.999", install_path:path);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
