# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808638");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2016-1225", "CVE-2016-1226");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-30 03:03:00 +0000 (Wed, 30 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-08-05 12:51:56 +0530 (Fri, 05 Aug 2016)");
  script_name("Trend Micro Internet Security Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Trend Micro Internet Security is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple input
  validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to access files on the device and also to execute arbitrary script
  on the products.");

  script_tag(name:"affected", value:"Trend Micro Internet Security version 8 and 10");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN48789425/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90999");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_trendmicro_internet_security_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("TrendMicro/IS/Installed");
  script_xref(name:"URL", value:"https://esupport.trendmicro.com/support/vb/solution/ja-jp/1113880.aspx");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );

treVer = infos['version'];
sysPath = infos['location'];
if( ! sysPath ) exit(0);

sysVer = fetch_file_version(sysPath:sysPath, file_name:"Titanium\plugin\plugDaemonHost.dll");
if(!sysVer){
  exit(0);
}

if(version_is_equal(version:treVer, test_version:"8.0") ||
   version_is_equal(version:treVer, test_version:"10.0")) {
  if(treVer =~ "^8"){
    minRequireVer = "8.0.0.2062";
  } else {
    ## After installing version 10 gives 9.0.0.1265
    minRequireVer = "9.0.0.1265";
  }

  if(version_is_less(version:sysVer, test_version:minRequireVer)) {
    report = report_fixed_ver(installed_version:treVer, fixed_version:"Apply the Patch", install_path:sysPath);
    security_message(data:report);
    exit(0);
  }
}

exit( 99 );
