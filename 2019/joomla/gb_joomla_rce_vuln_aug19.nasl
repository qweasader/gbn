# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113453");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-08-07 10:53:07 +0000 (Wed, 07 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-14654");

  script_name("Joomla! 3.9.7 and 3.9.8 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Inadequate filtering allows users authorised to create custom fields to
  manipulate the filtering options and inject an unvalidated option.
  The filter attribute in subform fields allows remote code execution.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  execute arbitrary code on the target system.");
  script_tag(name:"affected", value:"Joomla! versions 3.9.7 and 3.9.8.");
  script_tag(name:"solution", value:"Update to version 3.9.9.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/787-20190701-core-filter-attribute-in-subform-fields-allows-remote-code-execution.html");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.9.7", test_version2: "3.9.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
