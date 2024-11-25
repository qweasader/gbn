# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100117");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)");
  script_cve_id("CVE-2008-5917");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde XSS Filter XSS Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("horde_detect.nasl");
  script_mandatory_keys("horde/installed");

  script_tag(name:"summary", value:"Horde is prone to a cross-site scripting vulnerability because it fails to
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Horde 3.2.3 and 3.3.1 are vulnerable.

  Note that this issue also affects Turba on Horde IMP.");

  script_tag(name:"solution", value:"Update to version 3.2.3, 3.3.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33367");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:version, test_version:"3.3", test_version2:"3.3.0") ||
    version_in_range(version:version, test_version:"3.2", test_version2:"3.2.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.2.3/3.3.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
