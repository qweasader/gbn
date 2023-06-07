# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dolibarr:dolibarr";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112324");
  script_version("2023-05-09T09:12:26+0000");
  script_tag(name:"last_modification", value:"2023-05-09 09:12:26 +0000 (Tue, 09 May 2023)");
  script_tag(name:"creation_date", value:"2018-07-10 13:20:11 +0200 (Tue, 10 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-11 14:48:00 +0000 (Sat, 11 Aug 2018)");

  script_cve_id("CVE-2018-13447", "CVE-2018-13448", "CVE-2018-13449", "CVE-2018-13450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr <= 7.0.3 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dolibarr is prone to multiple SQL injection vulnerabilities in
  the following parameters:

  - statut (CVE-2018-13447)

  - country_id (CVE-2018-13448)

  - statut_buy (CVE-2018-13449)

  - status_batch (CVE-2018-13450)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary SQL commands on the target host.");

  script_tag(name:"affected", value:"Dolibarr version 7.0.3 and prior.");

  script_tag(name:"solution", value:"Update to version 8.0.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/commit/36402c22eef49d60edd73a2f312f8e28fe0bd1cb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "7.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
