# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807330");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3721", "CVE-2016-3722", "CVE-2016-3723", "CVE-2016-3724",
                "CVE-2016-3725", "CVE-2016-3726", "CVE-2016-3727");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-05-20 13:47:37 +0530 (Fri, 20 May 2016)");

  script_name("Jenkins Multiple Vulnerabilities (May 2016) - Linux");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The XML/JSON API endpoints providing information about installed plugins
    were missing permissions checks, allowing any user with read access to
    Jenkins to determine which plugins and versions were installed.

  - The users with extended read access could access encrypted secrets stored
    directly in the configuration of those items.

  - A missing permissions check allowed any user with access to Jenkins to trigger
    an update of update site metadata. This could be combined with DNS cache
    poisoning to disrupt Jenkins service.

  - The Some Jenkins URLs did not properly validate the redirect URLs, which
    allowed malicious users to create URLs that redirect users to arbitrary
    scheme-relative URLs.

  - The API URL /computer/(master)/api/xml allowed users with the 'extended read'
    permission for the master node to see some global Jenkins configuration,
    including the configuration of the security realm.

  - By changing the freely editable 'full name', malicious users with multiple
    user accounts could prevent other users from logging in, as 'full name' was
    resolved before actual user name to determine which account is currently trying
    to log in.

  - An improper validation of build parameters in Jenkins.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"All Jenkins main line releases up to and including 2.2,
  All Jenkins LTS releases up to and including 1.651.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 2.3,
  Jenkins LTS users should update to 1.651.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2016-05-11/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if( version_is_less( version:version, test_version:"1.651.2" ) ) {
    vuln = TRUE;
    fix = "1.651.2";
  }
} else {
  if( version_is_less( version:version, test_version:"2.3" ) ) {
    vuln = TRUE;
    fix = "2.3";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
