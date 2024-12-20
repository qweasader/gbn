# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118272");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-11-03 13:15:31 +0100 (Wed, 03 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 21:14:00 +0000 (Mon, 07 Dec 2020)");

  script_cve_id("CVE-2018-1000802");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python 2.7 Command Injection Vulnerability (Sep 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Python (CPython) version 2.7 contains a command injection
  vulnerability in shutil module.");

  script_tag(name:"impact", value:"This can result in Denial of service, Information gain via
  injection of arbitrary files on the system or entire drive. This attack appear to be
  exploitable via Passage of unfiltered user input to the function.

  This vulnerability appears to have been fixed in versions after commit
  'add531a1e55b0a739b0f42582f1c9747e5649ace'.");

  script_tag(name:"affected", value:"Python version 2.7.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue32056");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

# nb: No need for a version_regex as we only need versions like e.g. 2.7
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version =~ "^2\.7") {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
