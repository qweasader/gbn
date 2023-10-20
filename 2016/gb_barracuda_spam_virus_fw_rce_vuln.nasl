# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:barracuda_networks:barracuda_spam_firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106153");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-25 14:44:02 +0700 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Barracuda Spam and Virus Firewall Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_barracuda_spam_virus_firewall_detect.nasl");
  script_mandatory_keys("barracuda_spam_virus_fw/installed");

  script_tag(name:"summary", value:"Barracuda Spam & Virus Firewall is prone to a remote code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By sending a specially crafted request an authenticated attacker may
  inject system commands while escalating to root do to relaxed sudo configurations on the appliances.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary system commands.");

  script_tag(name:"affected", value:"Version <= 5.1.3.007.");

  script_tag(name:"solution", value:"Update to version 6.0.0.007 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138019/Barracuda-Spam-And-Virus-Firewall-5.1.3.007-Remote-Root.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.1.3.007")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.007");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
