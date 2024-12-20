# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112090");
  script_version("2024-07-26T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-07-26 15:38:40 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-10-20 11:47:18 +0200 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-25 12:45:00 +0000 (Wed, 25 Oct 2017)");

  script_cve_id("CVE-2017-15219");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("dotCMS 4.1.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_http_detect.nasl");
  script_mandatory_keys("dotcms/detected");

  script_tag(name:"summary", value:"dotCMS is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"dotCMS is vulnerable to stored XSS within multiple sections of
  the application. The application does not sanitize user supplied input and renders injected
  javascript code to the users browsers.");

  script_tag(name:"impact", value:"Attackers use this vulnerability to inject malicious javascript
  code such as a malicious redirect, crypto currency mining, or exploit kit.");

  script_tag(name:"affected", value:"dotCMS version 4.1.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/badbiddy/Vulnerability-Disclosure/master/dotCMS%20%3E%204.1.1%20-%20Stored%20XSS");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
