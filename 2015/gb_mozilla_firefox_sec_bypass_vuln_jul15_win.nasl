# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805915");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2015-2727");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-07-10 16:00:11 +0530 (Fri, 10 Jul 2015)");
  script_name("Mozilla Firefox Security Bypass Vulnerability (Jul 2015) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files, execute arbitrary JavaScript code and bypass
  security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version 38.0 on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 39.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-60");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75541");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_equal(version:ffVer, test_version:"38.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "39.0"  + '\n';
  security_message(data:report);
  exit(0);
}
