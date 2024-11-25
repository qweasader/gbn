# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2513");
  script_cve_id("CVE-2014-9496", "CVE-2014-9756", "CVE-2017-12562", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-6892", "CVE-2017-7586", "CVE-2017-7741", "CVE-2017-7742", "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365");
  script_tag(name:"creation_date", value:"2020-01-23 13:02:44 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-09 15:10:07 +0000 (Wed, 09 Aug 2017)");

  script_name("Huawei EulerOS: Security Advisory for libsndfile (EulerOS-SA-2019-2513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2513");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2513");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsndfile' package(s) announced via the EulerOS-SA-2019-2513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libsndfile before 1.0.28, an error in the 'header_read()' function (common.c) when handling ID3 tags can be exploited to cause a stack-based buffer overflow via a specially crafted FLAC file.(CVE-2017-7586)

Heap-based Buffer Overflow in the psf_binheader_writef function in common.c in libsndfile through 1.0.28 allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.(CVE-2017-12562)

In libsndfile 1.0.25 (fixed in 1.0.26), a divide-by-zero error exists in the function wav_w64_read_fmt_chunk() in wav_w64.c, which may lead to DoS when playing a crafted audio file.(CVE-2017-16942)

In libsndfile 1.0.28, a divide-by-zero error exists in the function double64_init() in double64.c, which may lead to DoS when playing a crafted audio file.(CVE-2017-14634)

The psf_fwrite function in file_io.c in libsndfile allows attackers to cause a denial of service (divide-by-zero error and application crash) via unspecified vectors related to the headindex variable.(CVE-2014-9756)

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()' function (flac.c) can be exploited to cause a segmentation violation (with write memory access) via a specially crafted FLAC file during a resample attempt, a similar issue to CVE-2017-7585.(CVE-2017-7741)

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()' function (flac.c) can be exploited to cause a segmentation violation (with read memory access) via a specially crafted FLAC file during a resample attempt, a similar issue to CVE-2017-7585.(CVE-2017-7742)

In libsndfile version 1.0.28, an error in the 'aiff_read_chanmap()' function (aiff.c) can be exploited to cause an out-of-bounds read memory access via a specially crafted AIFF file.(CVE-2017-6892)

The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows remote attackers to cause a denial of service (buffer overflow and application crash) or possibly have unspecified other impact via a crafted audio file.(CVE-2017-8361)

The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows remote attackers to cause a denial of service (invalid read and application crash) via a crafted audio file.(CVE-2017-8362)

The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted audio file.(CVE-2017-8363)

The i2les_array function in pcm.c in libsndfile 1.0.28 allows remote attackers to cause a denial of service (buffer over-read and application crash) via a crafted audio file.(CVE-2017-8365)

The sd2_parse_rsrc_fork function in sd2.c in libsndfile allows attackers to have unspecified impact via vectors related to a (1) map offset or (2) rsrc marker, which triggers an out-of-bounds read.(CVE-2014-9496)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.25~10.h11", rls:"EULEROS-2.0SP2"))) {
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
