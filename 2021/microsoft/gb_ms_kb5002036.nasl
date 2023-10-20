# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818907");
  script_version("2023-10-06T16:09:51+0000");
  script_cve_id("CVE-2021-40472", "CVE-2021-40474", "CVE-2021-40486");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-19 14:51:00 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 12:01:31 +0530 (Wed, 13 Oct 2021)");
  script_name("Microsoft Office Web Apps Server 2013 Service Pack 1 Multiple Vulnerabilities (KB5002036)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002036");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the presence of
  multiple errors when a maliciously modified file is opened in
  Microsoft SharePoint Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and gain access to sensitive data on the affected system.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps Server 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002036");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

CPE = "cpe:/a:microsoft:office_web_apps";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

webappVer = infos["version"];

path = infos["location"];
if(!path || "Could not find the install location" >< path)
  exit(0);

## Microsoft Office Web Apps 2013
if(webappVer =~ "^15\.")
{
  path = path + "\PPTConversionService\bin\Converter";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.5389.0999"))
    {
      report = report_fixed_ver(file_checked:path + "\msoserver.dll",
                                file_version:dllVer, vulnerable_range:"15.0 - 15.0.5389.0999");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
