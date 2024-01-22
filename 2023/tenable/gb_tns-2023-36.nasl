# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118562");
  script_version("2023-11-24T16:09:32+0000");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-23 12:46:50 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 16:43:00 +0000 (Thu, 14 Sep 2023)");

  script_cve_id("CVE-2023-4807", "CVE-2023-5847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Multiple Vulnerabilities (TNS-2023-36)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"One of the third-party components (OpenSSL) was found to contain
  vulnerabilities, and updated versions have been made available by the provider. Nessus 10.5.6
  updates OpenSSL to version 3.0.12 to address the identified vulnerabilities.

  Additionally, one other vulnerability was discovered, reported and fixed:

  - CVE-2023-5847: Under certain conditions, a low privileged attacker could load a specially
  crafted file during installation or upgrade to escalate privileges on Windows and Linux hosts.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.5.6.");

  script_tag(name:"solution", value:"Update to version 10.5.6 or later.

  Note: The installation files for version 10.5.6 can only be obtained via the Nessus
  Feed.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-36");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"10.5.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.5.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
