# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900043");
  script_version("2023-04-21T10:20:09+0000");
  script_tag(name:"last_modification", value:"2023-04-21 10:20:09 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-3282");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("OpenOffice.org < 3.2.0 'rtl_allocateMemory()' RCE Vulnerability - Linux");
  script_dependencies("gb_openoffice_ssh_login_detect.nasl");
  script_mandatory_keys("openoffice.org/linux/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31640/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30866");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2449");

  script_tag(name:"summary", value:"OpenOffice.org is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue is due to a numeric truncation error within the
  rtl_allocateMemory() method in alloc_global.c file.");

  script_tag(name:"impact", value:"Attackers can cause an out of bounds array access by tricking a
  user into opening a malicious document, also allow execution of arbitrary code.");

  script_tag(name:"affected", value:"OpenOffice.org 2.4.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.2.0 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"3.2.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
