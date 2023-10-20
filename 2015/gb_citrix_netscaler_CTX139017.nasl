# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105274");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-12 13:12:00 +0200 (Tue, 12 May 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2013-6011");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler DoS Vulnerability (CTX139017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Citrix Netscaler is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability, when exploited, could cause the Citrix
  NetScaler appliance to become temporarily unavailable for normal use.");

  script_tag(name:"affected", value:"Citrix NetScaler version 10.0 prior to 10.0-76.7.");

  script_tag(name:"solution", value:"Update to version 10.0-76.7 or later.");

  script_xref(name:"URL", value:"http://support.citrix.com/article/ctx139017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62788");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( get_kb_item( "citrix/netscaler/enhanced_build" ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE ) )
  exit( 0 );

if( vers =~ "^10\.0\." ) {
  if( version_is_less( version:vers, test_version: "10.0.76.7" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"10.0 build 76.7" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
