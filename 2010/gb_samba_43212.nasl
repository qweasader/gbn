# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100803");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-15 16:23:15 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3069");
  script_name("Samba SID Parsing Remote Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43212");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/history/samba-3.5.5.html");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CVE-2010-2069.html");

  script_tag(name:"summary", value:"Samba is prone to a remote stack-based buffer-overflow vulnerability
  because it fails to properly bounds-check user-supplied data before
  copying it to an insufficiently sized memory buffer.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will
  likely result in a denial of service.");

  script_tag(name:"affected", value:"Samba versions prior to 3.5.5 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if( version_is_less( version:vers, test_version:"3.5.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.5", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
