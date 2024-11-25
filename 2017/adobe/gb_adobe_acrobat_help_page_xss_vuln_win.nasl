# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812287");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2014-5315");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-12-29 11:29:42 +0530 (Fri, 29 Dec 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Acrobat Help Page Cross Site Scripting Vulnerability - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an input validation
  error in Help page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Acrobat 9.5.2 and earlier.");

  script_tag(name:"solution", value:"Upgrade to latest version of Adobe Acrobat
  according to the information provided by the developer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN84376800/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69791");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2014/JVNDB-2014-000105.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
adVer = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:adVer, test_version:"9.5.2"))
{
  report = report_fixed_ver(installed_version:adVer, fixed_version:"Upgrade to latest version according to the information provided by the developer", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
