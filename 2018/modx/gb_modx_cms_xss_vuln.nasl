# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:modx:revolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112291");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2018-06-04 11:48:33 +0200 (Mon, 04 Jun 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-27 19:26:00 +0000 (Wed, 27 Jun 2018)");

  script_cve_id("CVE-2018-10382", "CVE-2017-5223");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX Revolution CMS 2.6.3 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution CMS is prone to a stored cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MODX Revolution version 2.6.3 and probably prior.");

  script_tag(name:"solution", value:"Apply the changes from the referenced github commit / pull request.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/modxcms/revolution/v2.6.4-pl/core/docs/changelog.txt");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13887");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13887/commits/3241473d8213e9551cef4ed0e8ac4645cfbd10c4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply the changes from the linked commit / pull request");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
