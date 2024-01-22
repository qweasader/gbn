# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113204");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-05-29 16:04:31 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 13:57:00 +0000 (Tue, 06 Jul 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-11472", "CVE-2018-11473", "CVE-2018-11474", "CVE-2018-11475",
                "CVE-2018-18048", "CVE-2018-6383", "CVE-2018-6550", "CVE-2018-9037",
                "CVE-2018-9038", "CVE-2018-10109", "CVE-2018-10118", "CVE-2018-10121",
                "CVE-2018-11678", "CVE-2018-17418", "CVE-2018-14922", "CVE-2018-16608",
                "CVE-2018-15886", "CVE-2018-17026", "CVE-2018-17024", "CVE-2018-17025",
                "CVE-2018-16979", "CVE-2018-16977", "CVE-2018-16978", "CVE-2018-16819",
                "CVE-2018-18694", "CVE-2018-16820", "CVE-2018-11227", "CVE-2020-8439",
                "CVE-2020-13384", "CVE-2020-23205", "CVE-2020-23219", "CVE-2020-23697");

  script_name("Monstra CMS <= 3.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_monstra_cms_detect.nasl");
  script_mandatory_keys("monstra_cms/detected");

  script_tag(name:"summary", value:"Monstra CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Reflected XSS during Login

  - XSS in the registration Form

  - A password change at admin/index.php?id=users&action=edit&user_id=1 or users/1/edit does not invalidate a session that is open in a different browser

  - Arbitrary file upload vulnerability for example because .php (lowercase) is blocked but .PHP (uppercase) is not

  - Monstra CMS has an incomplete 'forbidden types' list that excludes .php (and similar) file extensions
    but not the .pht or .phar extension, which leads to arbitrary file upload.

  - XSS in the title function in plugins/box/pages/pages.plugin.php via a page title to admin/index.php

  - RCE via an upload_file request for a .zip file, which is automatically extracted and may contain .php files.

  - File deletion vulnerability via an admin/index.php?id=filesmanager&delete_dir=./&path=uploads/ request

  - Stored XSS vulnerability when an attacker has access to the editor role,
    and enters the payload in the content section of a new page in the blog catalog.

  - Stored XSS via the Name field on the Create New Page screen under the admin/index.php?id=pages URI

  - Stored XSS vulnerability in plugins/box/pages.admin.php when an attacker has access to the editor role,
    and enters the payload in the title section of an admin/index.php?id.pages&action.edit_page&name.error404 action.

  - plugins/box/users/users.plugin.php allows Login Rate Limiting Bypass via manipulation of the login_attempts cookie.

  - Multiple XSS vulnerabilities via the first name or last name field in the edit profile page.

  - An attacker with 'Editor' privileges can change the password of the administrator via an Insecure Direct Object Reference
    in admin/index.php?id=users&action=edit&user_id=1.

  - Monstra does not properly restrict modified Snippet content, as demonstrated by the
    admin/index.php?id=snippets&action=edit_snippet&filename=google-analytics URI,
    which leads to arbitrary code execution.

  - The admin/index.php page allows XSS via the page_meta_title parameter in an edit_page&name=error404 action,
    an add_page action or an edit_page action.

  - HTTP header injection in the plugins/captcha/crypt/cryptographp.php cfg parameter.

  - Information leakage risk (e.g., PATH, DOCUMENT_ROOT, and SERVER_ADMIN)
    in libraries/Gelato/ErrorHandler/Resources/Views/Errors/exception.php.

  - XSS vulnerability when one tries to register an account with a crafted password parameter to users/registration.

  - Arbitrary file deletion vulnerability in admin/index.php.

  - Stored XSS vulnerability in admin/index.php?id=filesmanager via
    JavaScript content in a file whose name lacks an extension.

  - Arbitrary directory listing vulnerability in admin/index.php.

  - XSS via index.php.

  - A remote authenticated user may take over arbitrary user accounts via a modified login parameter to an edit URI.

  - Remote authenticated users may upload and execute arbitrary PHP code via admin/index.php?id=filesmanager
    because, for example, .php filenames are blocked but .php7 filenames are not.

  - Remote code execution via the 'Snippet content' field in the 'Edit Snippet' module.

  - XSS via the 'Site Name' field in the 'Site Settings' module.

  - XSS via the page feature in admin/index.php.");
  script_tag(name:"affected", value:"Monstra CMS through version 3.0.4.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.

  Note: Monstra CMS is deprecated / not supported anymore by the vendor.");

  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/443");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/444");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/445");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/446");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/463");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/465");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/466");

  exit(0);
}

CPE = "cpe:/a:monstra:monstra";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
