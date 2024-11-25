# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:openoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805611");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-1774");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-05-11 10:05:48 +0530 (Mon, 11 May 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apache OpenOffice Multiple Vulnerabilities -02 (May 2015) - Mac OS X");

  script_tag(name:"summary", value:"Apache OpenOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an overflow condition
  in the Hangul Word Processor (HWP) filter that is triggered as user-supplied
  input is not properly validated");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to cause a denial of service or possibly execute arbitrary
  code via a crafted HWP document access.");

  script_tag(name:"affected", value:"Apache OpenOffice before 4.1.2 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Apache OpenOffice version
  4.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74338");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2015-1774.html");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openoffice_detect_macosx.nasl");
  script_mandatory_keys("OpenOffice/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## CPE is changed for newer versions of OpenOffice
if(!openoffcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:openoffcVer, test_version:"4.1.1"))
{
  report = 'Installed version: ' + openoffcVer + '\n' +
           'Fixed version:     ' + "4.1.2" + '\n';
  security_message(data:report);
  exit(0);
}
