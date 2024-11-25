# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2490");
  script_cve_id("CVE-2016-9398", "CVE-2017-13748", "CVE-2017-13751", "CVE-2017-6852", "CVE-2018-19539", "CVE-2018-19540", "CVE-2018-19541", "CVE-2018-19542", "CVE-2018-9055");
  script_tag(name:"creation_date", value:"2020-01-23 13:01:19 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-07 18:49:31 +0000 (Fri, 07 Dec 2018)");

  script_name("Huawei EulerOS: Security Advisory for jasper (EulerOS-SA-2019-2490)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2490");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2490");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'jasper' package(s) announced via the EulerOS-SA-2019-2490 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The jpc_floorlog2 function in jpc_math.c in JasPer before 1.900.17 allows remote attackers to cause a denial of service (assertion failure) via unspecified vectors.(CVE-2016-9398)

JasPer 2.0.14 allows denial of service via a reachable assertion in the function jpc_firstone in libjasper/jpc/jpc_math.c.(CVE-2018-9055)

An issue was discovered in JasPer 2.0.14. There is an access violation in the function jas_image_readcmpt in libjasper/base/jas_image.c, leading to a denial of service.(CVE-2018-19539)

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer overflow of size 1 in the function jas_icctxtdesc_input in libjasper/base/jas_icc.c.(CVE-2018-19540)

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer over-read of size 8 in the function jas_image_depalettize in libjasper/base/jas_image.c.(CVE-2018-19541)

An issue was discovered in JasPer 2.0.14. There is a NULL pointer dereference in the function jp2_decode in libjasper/jp2/jp2_dec.c, leading to a denial of service.(CVE-2018-19542)

There are lots of memory leaks in JasPer 2.0.12, triggered in the function jas_strdup() in base/jas_string.c, that will lead to a remote denial of service attack.(CVE-2017-13748)

There is a reachable assertion abort in the function calcstepsizes() in jpc/jpc_dec.c in JasPer 2.0.12 that will lead to a remote denial of service attack.(CVE-2017-13751)

Heap-based buffer overflow in the jpc_dec_decodepkt function in jpc_t2dec.c in JasPer 2.0.10 allows remote attackers to have unspecified impact via a crafted image.(CVE-2017-6852)");

  script_tag(name:"affected", value:"'jasper' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~33.h3", rls:"EULEROS-2.0SP2"))) {
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
