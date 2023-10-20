# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118271");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-11-03 13:15:31 +0100 (Wed, 03 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 22:15:00 +0000 (Tue, 21 Jan 2020)");

  script_cve_id("CVE-2017-18207");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.7.0 DoS Vulnerability (Mar 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Wave_read._read_fmt_chunk function in Lib/wave.py does
  not ensure a nonzero channel value.");

  script_tag(name:"impact", value:"This vulnerability allows attackers to cause a DoS (divide-by-zero
  and exception) via a crafted wav format audio file.

  Note: CVE is disputed by vendor, although fixes have been applied.");

  script_tag(name:"affected", value:"Python through version 3.6.4.");

  script_tag(name:"solution", value:"Update to Python version 3.7.0 or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue32056");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

# nb: No need for a version_regex as we only need versions like e.g. 2.7 or 3.9
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.7.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
