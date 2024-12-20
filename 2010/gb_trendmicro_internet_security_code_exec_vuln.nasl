# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801264");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_cve_id("CVE-2010-3189");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Trend Micro Internet Security Pro 'UfPBCtrl.dll' Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_trendmicro_internet_security_detect.nasl");
  script_mandatory_keys("TrendMicro/IS/Installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61397");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2185");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-165/");
  script_xref(name:"URL", value:"http://esupport.trendmicro.com/pages/Hot-Fix-UfPBCtrldll-is-vulnerable-to-remote-attackers.aspx");
  script_xref(name:"URL", value:"http://solutionfile.trendmicro.com/solutionfile/EN-1056426/TISPro_1750_win_en_hfb1695.exe");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the system with the privileges of the victim.");
  script_tag(name:"affected", value:"Trend Micro Internet Security Pro 2010");
  script_tag(name:"insight", value:"The flaw is caused by an error in the 'extSetOwner()' function within the
  'UfPBCtrl.dll' ActiveX control when processing user-supplied parameters,
  which could be exploited by remote attackers to execute arbitrary code by
  tricking a user into visiting a specially crafted web page.");
  script_tag(name:"summary", value:"Trend Micro Internet Security Pro is prone to a code execution vulnerability.");
  script_tag(name:"solution", value:"Apply the hotfix from the references.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_equal( version:vers, test_version:"17.50" ) ){
  report = report_fixed_ver( installed_version:vers, fixed_version:"17.50 Hotfix 1695", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );