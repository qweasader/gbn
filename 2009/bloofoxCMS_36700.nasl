# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bloofox:bloofoxcms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100312");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4522");

  script_name("bloofoxCMS 'search' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36700");
  script_xref(name:"URL", value:"http://www.bloofox.com/cms/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("bloofoxCMS_detect.nasl");
  script_mandatory_keys("bloofoxcms/installed");

  script_tag(name:"summary", value:"bloofoxCMS is prone to a cross-site scripting vulnerability because the
  application fails to sufficiently sanitize user-supplied input passed through the 'search' parameter.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"This issue affects bloofoxCMS 0.3.5. Other versions may be vulnerable as well.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 0.4.0 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.4.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);