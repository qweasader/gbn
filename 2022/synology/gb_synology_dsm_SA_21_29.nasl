# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170236");
  script_version("2023-12-07T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-11-18 13:30:55 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 14:59:00 +0000 (Thu, 10 Mar 2022)");

  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2020-25718", "CVE-2020-25719",
                "CVE-2020-25721", "CVE-2020-25722", "CVE-2021-3738", "CVE-2021-23192");

  # nb: Seems that the affected component needs to be update separately
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager Multiple Samba Vulnerabilities (Synology-SA-21:29)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities in Samba.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws in Samba exist:

  - CVE-2016-2124: SMB1 improper authentication

  - CVE-2020-25717: Privilege escalation due to a flaw in the way Samba maps domain users to
  local users

  - CVE-2020-25718: Missing authorization in the read-only domain controller support

  - CVE-2020-25719: Improper authentication in the Kerberos name-based authentication

  - CVE-2020-25721: Improper input validation

  - CVE-2020-25722: Multiple flaws in the way samba AD DC implemented access and conformance
  checking of stored data.

  - CVE-2021-3738: Use-after-free in the 'association groups' mechanism

  - CVE-2021-23192: Possible signature bypass in handling fragments of very large DCE/RPC
  requests.");

  script_tag(name:"affected", value:"Synology DiskStation Manager versions 6.2.x.");

  script_tag(name:"solution", value:"- Update SMB Service to version 4.15.13-0781 or later

  - Update Synology Directory Server to version 4.15.13-0615 or later

  Please see the referenced vendor advisory for further information.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_21_29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: Advisory only marks DSM 6.2 as affected
if( version =~ "^6\.2" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
