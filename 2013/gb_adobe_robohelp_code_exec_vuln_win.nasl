# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803771");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-5327");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-17 16:38:27 +0530 (Thu, 17 Oct 2013)");
  script_name("Adobe RoboHelp Arbitrary Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"Adobe RoboHelp is prone to an arbitrary code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error and can be exploited to cause
memory corruption.");
  script_tag(name:"affected", value:"Adobe RoboHelp version 10.x on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service (application crash).");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62887");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Adobe/RoboHelp/Win/Ver", "Adobe/RoboHelp/Win/InstallPath");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!arhVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(arhVer =~ "^10.*")
{
  dllPath = get_kb_item("Adobe/RoboHelp/Win/InstallPath");

  ## Exit if install location is not available
  if(dllPath && "Could not find the install location" >< dllPath){
    exit(0);
  }

  dllVer = fetch_file_version(sysPath:dllPath, file_name:"\RoboHTML\MDBMS.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.1.293"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
