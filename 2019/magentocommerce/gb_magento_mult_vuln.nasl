# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:magentocommerce:magento';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141927");
  script_version("2024-02-21T05:06:27+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-01-25 16:26:16 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # patch version not retrievable

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento Multiple Vulnerabilities (Nov 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento is prone to multiple vulnerabilities:

  - PHP Object Injection (POI) and Remote Code Execution

  - PHP Object Injection (POI) and Remote Code Execution

  - Unauthorized File Upload via Customer Attributes

  - Remote Code Execution through Path Traversal

  - Remote Code Execution through the Admin

  - Remote Code Execution in Upload of Quote File

  - Remote Code Execution Vulnerability in Race Condition

  - API-Based Remote Code Execution Vulnerability

  - Remote Code Execution through Unauthorized File Upload

  - Remote Code Execution and Arbitrary Move File

  - Unauthorized read permissions through Email Templates

  - Bypass of Authorization Check by Unauthorized Users

  - Cross-Site Scripting in the Swagger Generator through Unsanitized URL Parameter

  - Vulnerability in Customer Shopping Cart

  - Vulnerability in Staging Campaign Name

  - Vulnerability in Newsletter Template

  - Customer Gift Card Vulnerability

  - Vulnerability within Return Order Requests

  - Remote Code Execution through the Product Media Upload in the Admin

  - Vulnerability in Admin Alert Message

  - Widget Based XSS Vulnerability

  - Unauthorized Modification of the feed_url Configuration Setting

  - ACL Bypass of Shopping Cart Price Rules

  - Stored Cross-Site Scripting (XSS) in Admin

  - Customer Bypass of Restrictions

  - Leakage of Custom PHP settings from .user.ini File

  - Bypass of Authorization Possible through Vulnerability in render_handle

  - Vulnerability in Cart

  - Password Protection via External Auth Injection

  - Vulnerability for Authenticated Users

  - Vulnerability in Attribute Group Name

  - CSRF Vulnerability related to Customer Group Deletion

  - Outdated jQuery Causes PCI Scanning Failure

  - Cross Site Data Leakage

  - Encryption Keys Stored in Plain Text

  - AngularJS and Setup Application are Vulnerable");

  script_tag(name:"solution", value:"Update to version 2.1.16, 2.2.7 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.2.7-and-2.1.16-security-update");
  script_xref(name:"URL", value:"https://blog.scrt.ch/2019/01/24/magento-rce-local-file-read-with-low-privilege-admin-rights/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.1", test_version2: "2.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2", test_version2: "2.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
