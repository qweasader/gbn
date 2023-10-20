# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805724");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2594");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-21 10:26:43 +0530 (Tue, 21 Jul 2015)");
  script_name("Oracle Virtualbox Unspecified Vulnerability July15 (Mac OS X)");

  script_tag(name:"summary", value:"Oracle VM virtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 4.0.32,
  4.1.40, 4.2.32, and 4.3.30 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version
  4.0.32, 4.1.40, 4.2.32, and 4.3.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75899");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.(0|1|2|3))")
{
  if(version_in_range(version:virtualVer, test_version:"4.0.0", test_version2:"4.0.31"))
  {
     fix = "4.0.32";
     VULN = TRUE;
  }

  if(version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.39"))
  {
    fix = "4.1.40";
    VULN = TRUE;
  }

  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.31"))
  {
    fix = "4.2.32";
    VULN = TRUE;
  }

  if(version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.29"))
  {
    fix = "4.3.30";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = 'Installed version: ' + virtualVer + '\n' +
             'Fixed version:     ' + fix + '\n';
    security_message(data:report);
    exit(0);
  }
}
