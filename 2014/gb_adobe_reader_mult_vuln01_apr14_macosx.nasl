# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804354");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0511", "CVE-2014-0512");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-01 14:33:35 +0530 (Tue, 01 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 (Apr 2014) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass sandbox restrictions,
execute arbitrary code and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader XI version 11.0.6 and probably other versions on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to version 11.0.07 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1029970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66205");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66512");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14033102");
  script_xref(name:"URL", value:"http://www.pwn2own.com/2014/03/pwn2own-results-for-wednesday-day-one");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^11\.") {
  if(version_is_equal(version:vers, test_version:"11.0.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
