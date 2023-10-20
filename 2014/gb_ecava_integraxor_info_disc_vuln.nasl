# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ecava:integraxor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804299");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0786");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-19 17:47:38 +0530 (Mon, 19 May 2014)");
  script_name("Ecava IntegraXor Account Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_detect.nasl");
  script_require_ports("Services/www", 7131);
  script_mandatory_keys("EcavaIntegraXor/Installed");

  script_tag(name:"summary", value:"Ecava IntegraXor is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an error allowing users to perform 'SELECT' queries on the
  database.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain knowledge of potentially
  sensitive information.");
  script_tag(name:"affected", value:"Ecava IntegraXor before version 4.1.4393");
  script_tag(name:"solution", value:"Upgrade to Ecava IntegraXor version 4.1.4393 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66554");
  script_xref(name:"URL", value:"http://ics-cert.us-cert.gov/advisories/ICSA-14-091-01");
  script_xref(name:"URL", value:"http://www.integraxor.com/blog/category/security/vulnerability-note/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.integraxor.com/index.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:ver, test_version:"4.1.4393" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"4.1.4393" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );