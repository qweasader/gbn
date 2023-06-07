# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:rankmath:seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112722");
  script_version("2023-05-26T09:09:36+0000");
  script_tag(name:"last_modification", value:"2023-05-26 09:09:36 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2020-04-02 09:19:12 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-07 19:47:00 +0000 (Tue, 07 Apr 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-11514", "CVE-2020-11515");

  script_name("WordPress Rank Math SEO Plugin < 1.0.41 Multiple REST API Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/seo-by-rank-math/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SEO by Rank Math' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Unauthenticated remote attacker can update arbitrary WordPress metadata, including the ability to
    escalate or revoke administrative privileges for existing users via the unsecured
    rankmath/v1/updateMeta REST API endpoint

  - Unauthenticated remote attackers can create new URIs via the unsecured
    rankmath/v1/updateRedirection REST API endpoint, causing an Open Redirect vulnerability");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain control
  over the target software or trick other users to open malicious websites.");

  script_tag(name:"affected", value:"WordPress SEO by Rank Math plugin through version 1.0.40.2.");

  script_tag(name:"solution", value:"Update to version 1.0.41 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/seo-by-rank-math/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/03/critical-vulnerabilities-affecting-over-200000-sites-patched-in-rank-math-seo-plugin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.0.41" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.41", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
