# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103216");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2011-2746");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");

  script_name("OTRS 'AdminPackageManager.pm' Local File Disclosure Vulnerability (OSA-2011-03)");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on computers running the vulnerable
  application. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to adequately
  validate user-supplied input.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a local file
  disclosure vulnerability.");

  script_tag(name:"affected", value:"OTRS versions 2.4.x prior to 2.4.11 and 3.x prior to 3.0.8.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49251");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2011-03-en/");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"2.4", test_version2:"2.4.10") ||
   version_in_range(version:vers, test_version:"3.0", test_version2:"3.0.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.11/3.0.8");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
