# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150783");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-28 04:38:34 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 14:34:00 +0000 (Wed, 06 Sep 2023)");

  script_cve_id("CVE-2023-41738", "CVE-2023-41739", "CVE-2023-41740", "CVE-2023-41741");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager < 1.3.1-9346-6 Multiple Vulnerabilities (Synology-SA-23:10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-41738: OS command injection

  - CVE-2023-41739: Uncontrolled resource consumption in File Functionality

  - CVE-2023-41740: Path traversal in the CGI component

  - CVE-2023-41741: Information disclosure in the CGI component");

  script_tag(name:"affected", value:"Synology Router Manager version 1.3.x prior to 1.3.1-9346-6.");

  script_tag(name:"solution", value:"Update to firmware version 1.3.1-9346-6 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_23_10");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((version =~ "^1\.3") && (revcomp(a: version, b: "1.3.1-9346-6") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
