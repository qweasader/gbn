# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805109");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-9093");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-28 19:08:34 +0530 (Fri, 28 Nov 2014)");
  script_name("LibreOffice RTF File Handling Multiple Vulnerabilities Nov14 (Mac OS X)");

  script_tag(name:"summary", value:"LibreOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to improper handling of
  rtf file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service (crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"LibreOffice version before 4.3.5
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to LibreOffice 4.3.5
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=86449");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71313");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(version_is_less(version:libreVer, test_version:"4.3.5"))
{
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"4.3.5");
  security_message(port:0, data:report);
  exit(0);
}
