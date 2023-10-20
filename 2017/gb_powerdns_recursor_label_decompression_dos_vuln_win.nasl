# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809856");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1868", "CVE-2015-5470");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-04 14:18:12 +0530 (Wed, 04 Jan 2017)");
  script_name("PowerDNS Recursor Label Decompression Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  handling of DNS packets by label decompression functionality.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash or consume excessive CPU resource.");

  script_tag(name:"affected", value:"PowerDNS Recursor 3.5.x, 3.6.x before 3.6.4,
  and 3.7.x before 3.7.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to PowerDNS Recursor 3.6.4, or 3.7.3.
  or later.");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032220");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74306");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2015-01");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl", "os_detection.nasl");
  script_mandatory_keys("powerdns/recursor/installed", "Host/runs_windows");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!dnsPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!infos = get_app_version_and_proto(cpe:CPE, port:dnsPort)){
  exit(0);
}

version = infos["version"];
proto = infos["proto"];

if(version_in_range(version:version, test_version:"3.5.0", test_version2:"3.6.3"))
{
  fix = "3.6.4";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"3.7.0", test_version2:"3.7.2"))
{
  fix = "3.7.3";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:dnsPort, proto:proto);
  exit(0);
}
