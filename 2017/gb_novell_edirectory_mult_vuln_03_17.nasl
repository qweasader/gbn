# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140224");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-9167", "CVE-2016-9168", "CVE-2017-5186");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-05 01:59:00 +0000 (Wed, 05 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-03-30 12:28:05 +0200 (Thu, 30 Mar 2017)");
  script_name("Novell eDirectory Multiple Vulnerabilities - Mar17");

  script_tag(name:"summary", value:"Novell / NetIQ eDirectory is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Security scan shows potential Clickjacking vulnerability (Bug 998565) (CVE-2016-9168)

  - Includes a security fix to address potential access inconsistencies (Bug 993219) (CVE-2016-9167)

  - Uses a deprecated MD5 hashing algorithm in a communications certificate (CVE-2017-5186)");

  script_tag(name:"affected", value:"Novell / NetIQ eDirectory versions prior to 9.0.2 Hotfix 2.");

  script_tag(name:"solution", value:"Upgrade to Novell / NetIQ eDirectory 9.0.2 Hotfix 2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7016794");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("novell_edirectory_detect.nasl");
  script_mandatory_keys("eDirectory/installed");
  script_require_ports("Services/ldap", 389, 636);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:novell:edirectory", "cpe:/a:netiq:edirectory" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! major = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if( major !~ "^9\." )
  exit( 99 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += ' SP' + sp;

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

if( version_is_less( version:major, test_version:"9.0.2" ) ||
    ( major == "9.0.2" && int( revision ) < 4000456 ) ) {
  report = report_fixed_ver(installed_version:instvers, fixed_version:"9.0.2 Hotfix 2");
  security_message(data:report, port:port);
  exit(0);
}

