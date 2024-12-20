# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpexperts:post_smtp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126437");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2023-07-20 10:32:43 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 12:46:00 +0000 (Wed, 12 Jul 2023)");

  script_cve_id("CVE-2021-4422");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Post SMTP Mailer/Email Log Plugin < 2.0.21 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/post-smtp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Post SMTP Mailer/Email Log' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CSRF due to missing or incorrect nonce validation on the
  handleCsvExport() function.");

  script_tag(name:"affected", value:"WordPress Post SMTP Mailer/Email Log plugin prior to
  version 2.0.21");

  script_tag(name:"solution", value:"Update to version 2.0.21 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/post-smtp/post-smtp-mailer-2020-cross-site-request-forgery-bypass");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"2.0.21" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.0.21", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
