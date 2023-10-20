# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808267");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2014-2068", "CVE-2014-2066", "CVE-2014-2065", "CVE-2014-2064",
                "CVE-2014-2063", "CVE-2014-2062", "CVE-2014-2061", "CVE-2014-2060",
                "CVE-2014-2058", "CVE-2013-7285", "CVE-2013-5573");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-08-05 09:47:29 +0530 (Fri, 05 Aug 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Feb 2014) - Linux");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper access restriction by 'BuildTrigger'.

  - Improper session handling by 'Winstone servlet container'.

  - Error in input control in PasswordParameterDefinition.

  - Error in handling of API tokens.

  - Error in 'loadUserByUsername' function in the
  hudson/security/HudsonPrivateSecurityRealm.java script.

  - Insufficient validation of user supplied input via iconSize cookie.

  - Session fixation vulnerability via vectors involving the 'override' of
    Jenkins cookies.

  - 'doIndex' function in hudson/util/RemotingDiagnostics.java script does not
    restrict accessing sensitive information via vectors related to heapDump.

  - An unspecified vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, hijack web sessions, conduct
  clickjacking attacks, inject arbitrary web script or HTML, bypass the
  protection mechanism, gain elevated privileges, bypass intended access
  restrictions and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line prior to 1.551, Jenkins LTS prior to 1.532.2.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.551,
  Jenkins LTS users should update to 1.532.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/02/21/2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65720");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2014-02-14/");

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
  if( version_is_less( version:version, test_version:"1.532.2" ) ) {
    vuln = TRUE;
    fix = "1.532.2";
  }
} else {
  if( version_is_less( version:version, test_version:"1.551" ) ) {
    vuln = TRUE;
    fix = "1.551";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
