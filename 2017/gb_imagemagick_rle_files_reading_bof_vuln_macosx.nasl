# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810503");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-10049");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:00:00 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-01-17 15:32:07 +0530 (Tue, 17 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 'coders/rle.c' Remote Buffer Overflow Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"ImageMagick is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer-overflow error
  in the 'coders/rle.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code in context of the application. Failed
  exploits may result in denial-of-service conditions.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-4
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.4-4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95180");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/3e9165285eda6e1bb71172031d3048b51bb443a4");
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

if(version_is_less(version:imVer, test_version:"6.9.4.4"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.4-4');
  security_message(data:report);
  exit(0);
}
