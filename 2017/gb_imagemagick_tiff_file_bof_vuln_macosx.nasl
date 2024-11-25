# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810298");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-10059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-25 01:59:00 +0000 (Sat, 25 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-01-17 15:23:55 +0530 (Tue, 17 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 'TIFF' File Buffer Overflow Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"ImageMagick is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exits as application fails to
  adequately bounds-check user-supplied data before copying it to an
  insufficiently sized memory buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code within the context of the application.
  Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-1
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.4-1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95206");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/58cf5bf4fade82e3b510e8f3463a967278a3e410");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.4.1"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.4-1');
  security_message(data:report);
  exit(0);
}
