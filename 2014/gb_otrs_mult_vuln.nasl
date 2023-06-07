# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804236");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2014-1471", "CVE-2014-1694");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2014-02-07 18:02:09 +0530 (Fri, 07 Feb 2014)");
  script_name("OTRS Multiple Vulnerabilities (OSA-2014-01, OSA-2014-02)");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Flaw is in State.pm script, which fail to sufficiently
  sanitize user supplied data

  - Multiple scripts in Kernel/Modules/ fails to perform certain actions via HTTP requests without
  performing any validity checks to verify the requests");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate SQL
  queries by injecting arbitrary SQL code or perform unauthorized actions in the context of a
  logged-in user.");

  script_tag(name:"affected", value:"OTRS versions 3.1.x prior to 3.1.19, 3.2.x prior to 3.2.14 and
  3.3.x prior to 3.3.4.");

  script_tag(name:"solution", value:"Update to version 3.1.19, 3.2.14, 3.3.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56644");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65241");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56655");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-02-sql-injection-issue");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-01-csrf-issue-customer-web-interface");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.13") ||
   version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.18") ||
   version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.19/3.2.14/3.3.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
