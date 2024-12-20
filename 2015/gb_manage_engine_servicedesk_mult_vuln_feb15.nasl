# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805138");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-1479", "CVE-2015-1480");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-02-12 17:19:03 +0530 (Thu, 12 Feb 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ZOHO ManageEngine ServiceDesk Plus (SDP) Multiple Vulnerabilities (Feb 2015)");

  script_tag(name:"summary", value:"ZOHO ManageEngine ServiceDesk Plus (SDP) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to the CreateReportTable.jsp
  script not properly sanitizing user-supplied input to the 'site' parameter
  and not properly restricting access to (1) getTicketData action to servlet
  /AJaxServlet or a direct request to (2) swf/flashreport.swf, (3) reports
  /flash/details.jsp, or (4) reports/CreateReportTable.jsp.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attackers to gain access to ticket information and inject or
  manipulate SQL queries in the back-end database, allowing for the
  manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"ZOHO ManageEngine ServiceDesk Plus (SDP)
  version before 9.0 build 9031");

  script_tag(name:"solution", value:"Upgrade to version 9.0 build 9031 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35890");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130079");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/service-desk/readme-9.0.html");
  script_xref(name:"URL", value:"http://www.rewterz.com/vulnerabilities/manageengine-servicedesk-sql-injection-vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
path = infos['location'];

if( version_is_less( version:version, test_version:"9.0b9031" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"9.0 (Build 9031)", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
