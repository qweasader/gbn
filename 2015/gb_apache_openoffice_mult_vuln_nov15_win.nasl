# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:openoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806701");
  script_version("2023-04-21T10:20:09+0000");
  script_cve_id("CVE-2015-5214", "CVE-2015-5213", "CVE-2015-5212", "CVE-2015-4551");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-04-21 10:20:09 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"creation_date", value:"2015-11-16 15:31:04 +0530 (Mon, 16 Nov 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Apache OpenOffice Multiple Vulnerabilities Nov15 (Windows)");

  script_tag(name:"summary", value:"Apache OpenOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Usage of stored LinkUpdateMode configuration information in OpenDocument
    Format files and templates when handling links.

  - Integer underflow when the configuration setting 'Load printer settings with
    the document' is enabled.

  - Integer overflow via a long DOC file.

  - Incorrect handling of bookmarks in DOC files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, cause a denial of service or
  possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Apache OpenOffice version before 4.1.2 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache OpenOffice version
  4.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2015-5214.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77486");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2015-5213.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2015-5212.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2015-4551.html");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!openoffcVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Appache OpenOffice version 4.1.2 is equal to 4.12.9782
if(version_is_less(version:openoffcVer, test_version:"4.12.9782"))
{
  report = 'Installed version: ' + openoffcVer + '\n' +
           'Fixed version:     4.1.2\n';
  security_message(data:report);
  exit(0);
}
