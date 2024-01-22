# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100728");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2010-2914", "CVE-2010-2989");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Web Server < 1.2.4 Plugin Unspecified XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus Web Server is prone to a cross-site scripting
  (XSS) vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Nessus Web Server 1.2.4 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41966");
  script_xref(name:"URL", value:"https://discussions.nessus.org/message/7245");
  script_xref(name:"URL", value:"http://www.nessus.org");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512645");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# nb: Maybe we can also update this in the future to use the relevant CPE instead?
if(!version = get_kb_item("tenable/nessus/http/" + port + "/web_server/version"))
  exit(0);

if(version_is_less(version:version, test_version:"1.2.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.2.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
