# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-605l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170313");
  script_version("2024-10-22T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2023-02-21 18:07:42 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-17 20:31:00 +0000 (Fri, 17 Feb 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2023-24343", "CVE-2023-24344", "CVE-2023-24345", "CVE-2023-24346",
                "CVE-2023-24347", "CVE-2023-24348", "CVE-2023-24349", "CVE-2023-24350",
                "CVE-2023-24351", "CVE-2023-24352", "CVE-2024-9532", "CVE-2024-9533",
                "CVE-2024-9534", "CVE-2024-9535", "CVE-2024-9549", "CVE-2024-9550",
                "CVE-2024-9551", "CVE-2024-9552", "CVE-2024-9553", "CVE-2024-9555",
                "CVE-2024-9556", "CVE-2024-9557", "CVE-2024-9558", "CVE-2024-9559",
                "CVE-2024-9561", "CVE-2024-9562", "CVE-2024-9563", "CVE-2024-9564",
                "CVE-2024-9565");

  script_name("D-Link DIR-605L <= 2.13B01 Multiple Stack Overflow Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-605L revision B devices are prone to multiple stack
  overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-24343: stack overflow via the curTime parameter at /goform/formSchedule.

  - CVE-2023-24344: stack overflow via the webpage parameter at /goform/formWlanGuestSetup.

  - CVE-2023-24345: stack overflow via the curTime parameter at /goform/formSetWanDhcpplus.

  - CVE-2023-24346: stack overflow via the wan_connected parameter at /goform/formEasySetupWizard3.

  - CVE-2023-24347: stack overflow via the webpage parameter at /goform/formSetWanDhcpplus.

  - CVE-2023-24348: stack overflow via the curTime parameter at /goform/formSetACLFilter.

  - CVE-2023-24349: stack overflow via the curTime parameter at /goform/formSetRoute.

  - CVE-2023-24350: stack overflow via the config.smtp_email_subject parameter at
  /goform/formSetEmail.

  - CVE-2023-24351: stack overflow via the FILECODE parameter at /goform/formLogin.

  - CVE-2023-24352: stack overflow via the webpage parameter at /goform/formWPS

  - CVE-2024-9532: buffer overflow via the webpage argument of the function formDeviceReboot
  of the file /goform/formAdvanceSetup

  - CVE-2024-9533: buffer overflow via the next_page argument of the function formAdvanceSetup
  of the file /goform/formDeviceReboot

  - CVE-2024-9534: buffer overflow via the webpage argument of the function formDeviceReboot
  of the file /goform/formAdvanceSetup

  - CVE-2024-9535: buffer overflow via the curTime argument of the function formEasySetupWWConfig
  of the file /goform/formEasySetupWWConfig

  - CVE-2024-9549: buffer overflow via the curTime argument of the function
  formEasySetupWizard/formEasySetupWizard2 of the file /goform/formEasySetupWizard

  - CVE-2024-9550: buffer overflow via the curTime argument of the function formLogDnsquery of the
  file /goform/formLogDnsquery

  - CVE-2024-9551: buffer overflow via the webpage argument of the function formSetWanL2TP of the
  file /goform/formSetWanL2TP

  - CVE-2024-9552: buffer overflow via the webpage argument of the function formSetWanNonLogin of
  the file /goform/formSetWanNonLogin

  - CVE-2024-9553: buffer overflow via the curTime argument of the function formdumpeasysetup of
  the file /goform/formdumpeasysetup

  - CVE-2024-9555: buffer overflow via the curTime argument of the function formSetEasy_Wizard of
  the file /goform/formSetEasy_Wizard

  - CVE-2024-9556: buffer overflow via the curTime argument of the function formSetEnableWizard of
  the file /goform/formSetEnableWizard

  - CVE-2024-9557: buffer overflow via the webpage argument of the function formSetWanPPPoE of
  the file /goform/formSetWanPPPoE

  - CVE-2024-9558: buffer overflow via the webpage argument of the function formSetWanPPTP of
  the file /goform/formSetWanPPTP

  - CVE-2024-9559: buffer overflow via the webpage argument of the function formWlanSetup of
  the file /goform/formWlanSetup

  - CVE-2024-9561: buffer overflow via the webpage argument of the function
  formSetWAN_Wizard51/formSetWAN_Wizard52");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev B through firmware version 2.13B01.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for DIR-605L has ended in 24.09.2019, therefore
  most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-605L");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/03");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/04");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/03");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/03");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/tree/main/D-Link/DIR-605L");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );
