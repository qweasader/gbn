# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810558");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2016-9773");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-23 16:09:00 +0000 (Thu, 23 Feb 2017)");
  script_tag(name:"creation_date", value:"2017-02-21 09:22:03 +0530 (Tue, 21 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 'IsPixelGray' Function Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"ImageMagick is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a heap-based buffer overflow
  error in the 'IsPixelGray' function in MagickCore/pixel-accessor.h script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (out-of-bounds heap read).");

  script_tag(name:"affected", value:"ImageMagick version 7.0.3-8 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 7.0.3-9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/12/02/11");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/12/01/imagemagick-heap-based-buffer-overflow-in-ispixelgray-pixel-accessor-h-incomplete-fix-for-cve-2016-9556");
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

if(imVer == "7.0.3.8")
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'7.0.3-9');
  security_message(data:report);
  exit(0);
}

exit(99);