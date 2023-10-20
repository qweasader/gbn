# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:modx:revolution';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140286");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-08 15:39:24 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-02 13:37:00 +0000 (Wed, 02 Aug 2017)");

  script_cve_id("CVE-2017-11744");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");
  script_name("MODX Revolution CMS XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution CMS is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In MODX Revolution, the 'key' and 'name' parameters in the System Settings
module are vulnerable to XSS. A malicious payload sent to connectors/index.php will be triggered by every user,
when they visit this module.");

  script_tag(name:"affected", value:"MODX Revolution prior version 2.6.4.");
  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/13564");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/blob/2.x/core/docs/changelog.txt#L81");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
