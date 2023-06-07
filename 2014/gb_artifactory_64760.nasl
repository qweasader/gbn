# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:jfrog:artifactory";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103919");
  script_cve_id("CVE-2013-7285");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-05-16T09:08:27+0000");

  script_name("Artifactory < 3.1.1.1 XStream RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64760");
  script_xref(name:"URL", value:"http://www.jfrog.com/confluence/display/RTF/Artifactory+3.1.1");

  script_tag(name:"last_modification", value:"2023-05-16 09:08:27 +0000 (Tue, 16 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 12:47:00 +0000 (Fri, 22 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-03-13 10:30:44 +0100 (Thu, 13 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_artifactory_detect.nasl");
  script_mandatory_keys("artifactory/installed");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the user running the affected application.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Artifactory prior to version 3.1.1.1 using a XStream library
  which is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution", value:"Update to version 3.1.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Artifactory is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"affected", value:"Artifactory versions prior to 3.1.1.1.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.1.1.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.1.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
