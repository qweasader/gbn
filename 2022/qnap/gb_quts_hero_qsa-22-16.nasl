# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170126");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-05-30 09:20:47 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 20:17:00 +0000 (Fri, 13 May 2022)");

  script_cve_id("CVE-2021-44051", "CVE-2021-44052", "CVE-2021-44053", "CVE-2021-44054");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-22-16)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported to affect QuTS hero:

  - CVE-2021-44051: Command injection vulnerability

  - CVE-2021-44052: Improper link resolution before file access ('link following') vulnerability

  - CVE-2021-44053: Cross-site scripting (XSS) vulnerability

  - CVE-2021-44054: Open redirect vulnerability");

  script_tag(name:"impact", value:"CVE-2021-44051: If exploited, this vulnerability allows remote
  attackers to run arbitrary commands.

  CVE-2021-44052: If exploited, this vulnerability allows remote attackers to traverse the file system
  to unintended locations and read or overwrite files.

  CVE-2021-44053: If exploited, this vulnerability allows remote attackers to inject malicious code.

  CVE-2021-44054: If exploited, this vulnerability allows attackers to redirect users to an untrusted
  page that contains malware.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.x prior to h4.5.4 build 20220310 and
  h5.0.0 prior to h5.0.0 build 20220324.");

  script_tag(name:"solution", value:"Update to version QuTS hero h4.5.4.1971 build 20220310,
  h5.0.0.1986 build 20220324 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-16");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/quts_hero/h5.0.0.1986/20220324");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/quts_hero/h4.5.4.1971/20220310");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/quts_hero/build" );

if ( version_is_less( version:version, test_version:"h4.5.4.1971" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h4.5.4.1971", fixed_build:"20220310" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"h4.5.4.1971" ) &&
   ( ! build || version_is_less( version:build, test_version:"20220310" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h4.5.4.1971", fixed_build:"20220310" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version =~ "^h5" ) {
  if ( version_is_less( version:version, test_version:"h5.0.0.1986" ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h5.0.0.1986", fixed_build:"20220324" );
    security_message( port:0, data:report );
    exit( 0 );
  }

  if ( version_is_equal( version:version, test_version:"h5.0.0.1986" ) &&
     ( ! build || version_is_less( version:build, test_version:"20220324" ) ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h5.0.0.1986", fixed_build:"20220324" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
