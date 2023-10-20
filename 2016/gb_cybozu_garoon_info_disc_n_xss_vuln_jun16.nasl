# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807850");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-7776", "CVE-2015-7775");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-21 18:01:00 +0000 (Tue, 21 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-06-30 09:39:45 +0530 (Thu, 30 Jun 2016)");
  script_name("Cybozu Garoon Information Disclosure And Cross-Site Scripting Vulnerabilities - Jun16");

  script_tag(name:"summary", value:"cybozu garoon is vulnerable to information disclosure and cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The application does not properly restrict loading of IMG elements.

  - An insufficient validation of input passed to unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML code and gain access to
  potentially sensitive information.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Cybozu Garoon versions 3.x and 4.x before
  4.2.0");

  script_tag(name:"solution", value:"Upgrade to Cybozu Garoon 4.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.cybozu.com/ja-jp/article/8757");
  script_xref(name:"URL", value:"https://support.cybozu.com/ja-jp/article/8897");
  script_xref(name:"URL", value:"https://support.cybozu.com/ja-jp/article/8951");
  script_xref(name:"URL", value:"https://support.cybozu.com/ja-jp/article/8982");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuGaroon/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://garoon.cybozu.co.jp");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!cyPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cyVer = get_app_version(cpe:CPE, port:cyPort)){
  exit(0);
}

if(version_in_range(version:cyVer, test_version:"3.0", test_version2:"4.0.3"))
{
  report = report_fixed_ver(installed_version:cyVer, fixed_version:"4.2.0");
  security_message(data:report, port:cyPort);
  exit(0);
}
