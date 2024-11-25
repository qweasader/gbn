# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dap-1533_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170620");
  script_version("2024-10-16T08:00:45+0000");
  script_tag(name:"last_modification", value:"2024-10-16 08:00:45 +0000 (Wed, 16 Oct 2024)");
  # nb: This was initially a single VT covering DAP and DHP devices but got later split in 2024 into
  # two separate VTs. As both devices have been covered back then in 2023 the original creation date
  # has been kept here.
  script_tag(name:"creation_date", value:"2023-02-24 21:18:49 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-10 21:15:00 +0000 (Thu, 10 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-16920");

  script_name("D-Link DAP-1533 Devices RCE Vulnerability (Sep 2019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1533 devices are prone to a remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"Any arguments after a newline character sent as ping_ipaddr in a
  POST to /apply_sec.cgi are executed on the device with root privileges.");

  script_tag(name:"affected", value:"D-Link DAP-1533 devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: CISA states that the impacted devices are end-of-life and should be disconnected if still
  in use.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/766427");
  script_xref(name:"URL", value:"https://www.fortiguard.com/zeroday/FG-VD-19-117");
  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-98079");
  script_xref(name:"URL", value:"https://80vul.medium.com/determine-the-device-model-affected-by-cve-2019-16920-by-zoomeye-bf6fec7f9bb3");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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
