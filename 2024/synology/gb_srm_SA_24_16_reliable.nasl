# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170887");
  script_version("2024-10-22T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-18 15:48:05 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager (SRM) 1.3.x Multiple Vulnerabilities (Synology-SA-24:16) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities allow remote authenticated users to
  read specific files containing non-sensitive information, remote authenticated users with admin
  privileges to execute arbitrary code, remote authenticated users with admin privileges to execute
  arbitrary commands and remote authenticated users with admin privileges to inject arbitrary web
  script or HTML via a susceptible version of Synology Router Manager (SRM).");

  script_tag(name:"affected", value:"SRM version 1.3.x prior to 1.3.1-9346-11.");

  script_tag(name:"solution", value:"Update to firmware version 1.3.1-9346-11 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_16");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 1.1.5-6542-4 and not 1.1.5-6542), there will be 2 VTs with different qod_type.
if (version =~ "^1\.3" && (revcomp(a: version, b: "1.3.1-9346") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-11");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.153160
if (version =~ "^1\.3\.1-9346")
  exit(0);

exit(99);
