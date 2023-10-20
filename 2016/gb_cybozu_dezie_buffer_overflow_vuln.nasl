# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:dezie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807423");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2014-5314");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:54 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Dezie Buffer Overflow Vulnerability Feb16");

  script_tag(name:"summary", value:"Cybozu Dezie is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  buffer overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial-of-service, or execute arbitrary code.");

  script_tag(name:"affected", value:"Cybozu Dezie version 8.1.0 and earlier.");
  script_tag(name:"solution", value:"Upgrade to Cybozu Dezie version 8.1.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN14691234/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71057");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuDezie/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://products.cybozu.co.jp/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cybPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cybVer = get_app_version(port:cybPort, cpe:CPE)){
  exit(0);
}

if (version_is_less(version:cybVer ,test_version:"8.1.1"))
{
  report = report_fixed_ver(installed_version:cybVer, fixed_version:"8.1.1");
  security_message(port:cybPort, data:report);
  exit(0);
}

exit(99);
