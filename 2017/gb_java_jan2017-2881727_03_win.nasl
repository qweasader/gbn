# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809784");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2016-5547", "CVE-2016-5549", "CVE-2017-3289", "CVE-2017-3260");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-01-18 18:42:46 +0530 (Wed, 18 Jan 2017)");
  script_name("Oracle Java SE Security Updates (jan2017-2881727) 03 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'Hotspot', 'Libraries' and 'AWT' sub-components.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow attackers to have some unspecified impacts
  on affected system.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.7.0.121 and
  earlier, 1.8.0.112 and earlier on Windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95530");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95576");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers =~ "^(1\.(7|8))")
{
  if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.121") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.112"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
