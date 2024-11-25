# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1129.1");
  script_cve_id("CVE-2017-1000476", "CVE-2017-10928", "CVE-2017-18251", "CVE-2017-18252", "CVE-2017-18254", "CVE-2018-10177", "CVE-2018-8960", "CVE-2018-9018");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-13 18:42:21 +0000 (Fri, 13 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1129-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181129-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:1129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:
- security update (png.c)
 * CVE-2018-9018: divide-by-zero in the ReadMNGImage function of
 coders/png.c. Attackers could leverage this vulnerability to cause a
 crash and denial of service via a crafted mng file. [bsc#1086773]
 * CVE-2018-10177: there is an infinite loop in the
 ReadOneMNGImagefunction of the coders/png.c file. Remote attackers
 could leverage thisvulnerability to cause a denial of service
 (bsc#1089781)
- security update (wand)
 * CVE-2017-18252: The MogrifyImageList function in MagickWand/mogrify.c
 could allow attackers to cause a denial of service via a crafted file.
 [bsc#1087033]
- security update (gif.c)
 * CVE-2017-18254: A memory leak vulnerability was found in the function
 WriteGIFImage in coders/gif.c, which could lead to denial of service
 via a crafted file. [bsc#1087027]
- security update (core)
 * CVE-2017-10928: a heap-based buffer over-read in the GetNextToken
 function in token.c could allow attackers to obtain sensitive
 information from process memory or possibly have unspecified other
 impact via a crafted SVG document that is mishandled in the
 GetUserSpaceCoordinateValue function in coders/svg.c. [bsc#1047356]
- security update (pcd.c)
 * CVE-2017-18251: A memory leak vulnerability was found in the function
 ReadPCDImage in coders/pcd.c, which could lead to a denial of service
 via a crafted file. [bsc#1087037]
- security update (gif.c)
 * CVE-2017-18254: A memory leak vulnerability was found in the function
 WriteGIFImage in coders/gif.c, which could lead to denial of service
 via a crafted file. [bsc#1087027]
- security update (tiff.c)
 * CVE-2018-8960: The ReadTIFFImage function in coders/tiff.c in
 ImageMagick memory allocation issue could lead to denial of service
 (bsc#1086782)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~78.45.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~78.45.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
