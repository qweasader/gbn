# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170129");
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

  script_name("QNAP QuTScloud Multiple Vulnerabilities (QSA-22-16)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported to affect QuTScloud:

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

  script_tag(name:"affected", value:"QNAP QuTScloud prior to c5.0.1.1998 build 20220408.");

  script_tag(name:"solution", value:"Update to version QuTScloud c5.0.1.1998 build 20220408 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-16");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qutscloud/c5.0.1.1998/20220408");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qutscloud/build" );

if ( version_is_less( version:version, test_version:"c5.0.1.1998" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c5.0.1.1998", fixed_build:"20220408" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"c5.0.1.1998" ) &&
   ( ! build || version_is_less( version:build, test_version:"20220408" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c5.0.1.1998", fixed_build:"20220408" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
