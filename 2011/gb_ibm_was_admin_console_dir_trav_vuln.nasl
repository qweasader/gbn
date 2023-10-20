# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801977");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-1359");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IBM WebSphere Application Server Administration Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49362");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69473");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21509257");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24028875");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files on the
  affected application and obtain sensitive information that may lead to further attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 6.1 before 6.1.0.41,
  7.0 before 7.0.0.19 and 8.0 before 8.0.0.1");

  script_tag(name:"insight", value:"The flaw is due to error in administration console which fails to
  handle certain requests. This allows remote attackers to read arbitrary files via a '../' (dot dot) in the URI.");

  script_tag(name:"solution", value:"Upgrade IBM WebSphere Application Server to 6.1.0.41 or 7.0.0.19 or
  8.0.0.1");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:vers, test_version:"8.0.0.0") ||
   version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.40") ||
   version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.18")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.0.41/7.0.0.19");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);