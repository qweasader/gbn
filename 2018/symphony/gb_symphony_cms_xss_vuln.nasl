# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112302");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2017-12043");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-11 13:17:23 +0200 (Mon, 11 Jun 2018)");

  script_name("Symphony CMS <= 2.7.6 XSS Vulnerability");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_mandatory_keys("symphony/installed");

  script_xref(name:"URL", value:"https://github.com/symphonycms/symphony-2/commit/1ace6b31867cc83267b3550686271c9c65ac3ec0");

  script_tag(name:"summary", value:"Symphony CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"content/content.blueprintspages.php in Symphony CMS has XSS via
  the pages content page.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"Symphony CMS versions through 2.7.6.");

  script_tag(name:"solution", value:"Update to version 2.7.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.7" , install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
