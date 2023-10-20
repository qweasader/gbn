# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810508");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-9915");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-24 14:04:00 +0000 (Fri, 24 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-01-18 11:29:40 +0530 (Wed, 18 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 8BIM Profile Parsing Off-By-One Count Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"ImageMagick is prone to an Off-by-one count vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an Off-by-one count
  error when parsing an 8BIM profile.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to trigger buffer overflows which can be used to execute
  arbitrary code and therefore crashes.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.8.9-9
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.8.9-9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.8.9.9"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.8.9-9');
  security_message(data:report);
  exit(0);
}
