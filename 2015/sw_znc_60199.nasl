# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111032");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-29 12:00:00 +0200 (Sat, 29 Aug 2015)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2013-2130");

  script_name("ZNC WebAdmin Multiple NULL Pointer Dereference Denial of Service Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_znc_consolidation.nasl");
  script_mandatory_keys("znc/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60199");

  script_tag(name:"summary", value:"ZNC is prone to multiple remote denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit these issues to crash the application, resulting
  in denial-of-service conditions.");

  script_tag(name:"affected", value:"These issues affect ZNC 1.0.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.2" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
