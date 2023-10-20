# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149874");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-05 03:57:19 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-10 13:29:00 +0000 (Mon, 10 Jul 2023)");

  script_cve_id("CVE-2023-36539");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client 5.15.0 Information Disclosure Vulnerability (ZSB-23025) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_macosx_detect.nasl");
  script_mandatory_keys("zoom/client/mac/detected");

  script_tag(name:"summary", value:"Zoom Client is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exposure of information intended to be encrypted by some Zoom
  clients may lead to disclosure of sensitive information.

  Zoom encrypts in-meeting chat messages using a per-meeting key and then transmits these encrypted
  messages between user devices and Zoom using TLS encryption. In the affected products, a copy of
  each in-meeting chat message was also sent encrypted only using TLS and not with the per-meeting
  key, including messages sent during End-to-End Encrypted (E2EE) meetings.");

  script_tag(name:"affected", value:"Zoom Client version 5.15.0.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "5.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
