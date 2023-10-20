# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801984");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-1509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ManageEngine ServiceDesk Plus Authentication Bypass Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105123/CORE-2011-0506.txt");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/multiples-vulnerabilities-manageengine-sdp");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/service-desk/readme-8.0.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to get user names
  and passwords of registered users. This may allow an attacker to steal
  cookie-based  authentications and launch further attacks.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in authentication process, User
  passwords are pseudo encrypted and locally stored in user cookies. Having
  Javascript code encrypt and decrypt passwords in Login.js file.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue, please refer
  below link for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to an authentication bypass vulnerability.");

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

if( version_is_less( version:version, test_version:"8.0b8014" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.0 (Build 8014)", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
