# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106961");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-18 11:04:20 +0700 (Tue, 18 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-08 18:14:00 +0000 (Thu, 08 Jun 2017)");

  script_cve_id("CVE-2017-9305");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"summary", value:"lib/core/TikiFilter/PreventXss.php in Tiki Wiki CMS Groupware allows remote
attackers to bypass the XSS filter via padded zero characters, as demonstrated by an attack on
tiki-batch_send_newsletter.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware 16.2.");

  script_tag(name:"solution", value:"Upgrade to version 17.0 or later.");

  script_xref(name:"URL", value:"https://github.com/tikiorg/tiki/commit/6c016e8f066d2f404b18eaa1af7fa0c7a9651ccd");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "16.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
