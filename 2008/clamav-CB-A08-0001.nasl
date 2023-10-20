# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90000");
  script_version("2023-10-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2008-02-29 23:43:58 +0100 (Fri, 29 Feb 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6335", "CVE-2007-6336", "CVE-2007-6337", "CVE-2008-0318", "CVE-2008-1100",
                "CVE-2008-1387", "CVE-2008-2713");
  script_name("ClamAV < 0.93.1 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_ssh_login_detect.nasl", "gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl");
  script_mandatory_keys("clamav/detected");

  script_tag(name:"solution", value:"All ClamAV users should update to the latest version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"- CVE 2008-2713: libclamav/petite.c in ClamAV before 0.93.1
  allows remote attackers to cause a denial of service via a crafted Petite file that triggers an
  out-of-bound read.

  - CVE 2008-1387: ClamAV before 0.93 allows remote attackers to cause a denial of service (CPU
  consumption) via a crafted ARJ archive, as demonstrated by the PROTOS GENOME test suite for
  Archive Formats.

  - CVE 2008-1100: Buffer overflow in the cli_scanpe function in libclamav (libclamav/pe.c) for
  ClamAV 0.92 and 0.92.1 allows remote attackers to execute arbitrary code via a crafted Upack PE
  file.

  - CVE 2008-0318: Integer overflow in the cli_scanpe function in libclamav in ClamAV before 0.92.1,
  as used in clamd, allows remote attackers to cause a denial of service and possibly execute
  arbitrary code via a crafted Petite packed PE file, which triggers a heap-based buffer overflow.

  - CVE 2007-6337: Unspecified vulnerability in the bzip2 decompression algorithm in
  nsis/bzlib_private.h in ClamAV before 0.92 has unknown impact and remote attack vectors.

  - CVE 2007-6336: off-by-one error in ClamAV before 0.92 allows remote attackers to execute
  arbitrary code via a crafted MS-ZIP compressed CAB file.

  - CVE 2007-6335: Integer overflow in libclamav in ClamAV before 0.92 allows remote attackers to
  execute arbitrary code via a crafted MEW packed PE file, which triggers a heap-based buffer
  overflow.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"0.93.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.93.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
