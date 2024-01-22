# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118549");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-02 15:15:15 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-19 12:44:00 +0000 (Thu, 19 Oct 2023)");

  script_cve_id("CVE-2023-3446", "CVE-2023-3817", "CVE-2023-4807", "CVE-2023-5847",
                "CVE-2023-45853");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent 10.4.2 Multiple Vulnerabilities (TNS-2023-38)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus Agent leverages third-party software to help provide
  underlying functionality. Several of the third-party components (OpenSSL, zlib) were found to
  contain vulnerabilities, and updated versions have been made available by the providers.

  Out of caution and in line with best practice, Tenable has opted to upgrade these components
  to address the potential impact of the issues. Nessus Agent 10.4.3 updates OpenSSL to version
  3.0.12 and zlib fixes have been applied to address the identified vulnerabilities.

  Additionally, one other vulnerability was discovered, reported and fixed:

  - CVE-2023-5847: Under certain conditions, a low privileged attacker could load a specially
  crafted file during installation or upgrade to escalate privileges on Windows and Linux hosts.");

  script_tag(name:"affected", value:"Tenable Nessus Agent version 10.4.2.");

  script_tag(name:"solution", value:"Update to version 10.4.3 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-38");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version:version, test_version:"10.4.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.4.3", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
