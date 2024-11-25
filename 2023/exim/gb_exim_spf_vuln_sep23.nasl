# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151116");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. To avoid wrong stats about CVE coverage the "creation_date" of the original VT
  # has been kept here because all CVEs had been covered at this time.
  script_tag(name:"creation_date", value:"2023-09-29 04:31:53 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-42118");

  # TODO: needs to be adjusted once a fix is available, see also note below.
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Exim <= 4.96.2 libspf2 RCE Vulnerability (Sep 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a remote code execution (RCE) vulnerability
  in libspf2.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific flaw exists within the parsing of SPF macros. When
  parsing SPF macros, the process does not properly validate user-supplied data, which can result
  in an integer underflow before writing to memory. An attacker can leverage this vulnerability to
  execute code in the context of the service account.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://www.exim.org/static/doc/security/CVE-2023-zdi.txt");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1472/");
  # nb: This thread should be re-checked in the future but so far it is not clear even what / where is the actual problem
  script_xref(name:"URL", value:"https://github.com/shevek/libspf2/issues/45");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

report = report_fixed_ver(installed_version: version, fixed_version: "None");
security_message(port: port, data: report);
exit(0);
