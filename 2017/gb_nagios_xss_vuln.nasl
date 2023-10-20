# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:nagios:nagios';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108136");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-13 12:06:51 +0200 (Thu, 13 Apr 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-04 18:46:00 +0000 (Tue, 04 Apr 2017)");
  script_cve_id("CVE-2016-6209");

  script_name("Nagios 'corewindow' Parameter Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nagios fails to properly sanitize user-supplied input to the 'corewindow'
parameter of 'index.php'");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary script code in the
browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal
cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Nagios versions before 4.3.0.");

  script_tag(name:"solution", value:"Update to Nagios 4.3.0 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/20");
  script_xref(name:"URL", value:"https://www.nagios.org/projects/nagios-core/history/4x/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
