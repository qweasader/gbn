# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805605");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1774");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-05 18:00:52 +0530 (Tue, 05 May 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice Multiple Vulnerabilities May15 (Mac OS X)");

  script_tag(name:"summary", value:"LibreOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an overflow condition
  in the Hangul Word Processor (HWP) filter that is triggered as user-supplied
  input is not properly validated");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to cause a denial of service or possibly execute arbitrary
  code via a crafted HWP document access.");

  script_tag(name:"affected", value:"LibreOffice version before 4.3.7 and 4.4.x before
  4.4.2 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version
  4.3.7 or 4.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2015-1774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74338");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!libreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:libreVer, test_version:"4.3.7"))
{
  VULN = TRUE;
  fix = "4.3.7";
}

if(version_in_range(version:libreVer, test_version:"4.4.0", test_version2:"4.4.1"))
{
  VULN = TRUE;
  fix = "4.4.2";
}

if(VULN)
{
  report = 'Installed version: ' + libreVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}
