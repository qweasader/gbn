# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124413");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-18 08:15:22 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-24 21:02:00 +0000 (Wed, 24 May 2023)");

  script_cve_id("CVE-2023-32068");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 14.10.4 Open Redirect Vulnerability (GHSA-6gvj-8vc5-8v3j)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It's possible to exploit well known parameters in XWiki URLs to
  perform redirection to untrusted site.");

  script_tag(name:"affected", value:"XWiki version prior to 14.10.4.");

  script_tag(name:"solution", value:"Update to version 14.10.4 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-6gvj-8vc5-8v3j");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "14.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.10.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
