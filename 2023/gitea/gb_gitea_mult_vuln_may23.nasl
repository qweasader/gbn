# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitea:gitea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170460");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-09 18:49:38 +0000 (Tue, 09 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 18:22:00 +0000 (Mon, 22 May 2023)");

  script_cve_id("CVE-2023-24539", "CVE-2023-24540", "CVE-2023-29400");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea < 1.19.3 Multiple golang Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_gitea_http_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea is prone to multiple vulnerabilities in golang.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist in golang:

  - CVE-2023-24539: Angle brackets are not considered dangerous characters when inserted into CSS
  contexts. Templates containing multiple actions separated by a '/' character could result in
  unexpectedly closing the CSS context and allowing for injection of unexpected HTML, if executed
  with untrusted input.

  - CVE-2023-24540: Not all valid JavaScript whitespace characters are considered to be whitespace.
  Templates containing other whitespace characters in JavaScript contexts that also contain actions
  may not be properly sanitized during execution.

  - CVE-2023-29400: Templates containing actions in unquoted HTML attributes executed with empty
  input could result in output that would have unexpected results when parsed due to HTML
  normalization rules. This may allow injection of arbitrary attributes into tags.");

  script_tag(name:"affected", value:"Gitea prior to version 1.19.3.");

  script_tag(name:"solution", value:"Update to version 1.19.3 or later.");

  script_xref(name:"URL", value:"https://blog.gitea.io/2023/05/gitea-1.19.3-is-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.19.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
