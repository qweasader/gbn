# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pandasecurity:panda_internet_security_2014";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107092");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2014-3450");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-21 09:18:47 +0100 (Mon, 21 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Privilege Escalation in Panda Internet Security 2014 CVE-2014-3450 (Windows)");
  script_xref(name:"URL", value:"http://www.anti-reversing.com/cve-2014-3450-privilege-escalation-in-panda-security/");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-3450/");
  script_tag(name:"qod", value:"30");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/InternetSecurity/Ver");
  script_tag(name:"affected", value:"Panda Internet Security v19.01.01");
  script_tag(name:"insight", value:"As the USERS group has write permissions over the folder where the PSEvents.exe
process is located, it is possible to execute malicious code as Local System.");
  script_tag(name:"solution", value:"Install Panda Hotfix for this vulnerability, see the vendor advisory.");
  script_tag(name:"summary", value:"Panda Products is prone to a Privilege
Escalation Vulnerability.");
  script_tag(name:"impact", value:"This vulnerability allows for privilege escalation on the local system.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers  = infos['version'];
path  = infos['location'];

if( version_is_equal( version:vers, test_version:"19.01.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( data:report );
  exit( 0 );
}

exit( 99 );
