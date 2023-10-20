# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805729");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2659");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-20 17:10:19 +0530 (Mon, 20 Jul 2015)");
  script_name("Oracle Java SE JRE Unspecified Vulnerability-04 July 2015 (Windows)");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error is due to unspecified
  flaws related to unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on availability.");

  script_tag(name:"affected", value:"Oracle Java SE 8 update 45 on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75877");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(jreVer =~ "^(1\.8)")
{
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.45"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch from the referenced advisory.");
    security_message(data:report);
    exit(0);
  }
}
