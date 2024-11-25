# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2237");
  script_cve_id("CVE-2008-3521", "CVE-2016-10250", "CVE-2016-8887", "CVE-2017-6850", "CVE-2017-6852");
  script_tag(name:"creation_date", value:"2020-01-23 12:42:28 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-16 18:49:13 +0000 (Thu, 16 Mar 2017)");

  script_name("Huawei EulerOS: Security Advisory for jasper (EulerOS-SA-2019-2237)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2237");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2237");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'jasper' package(s) announced via the EulerOS-SA-2019-2237 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The jp2_colr_destroy function in libjasper/jp2/jp2_cod.c in JasPer before 1.900.10 allows remote attackers to cause a denial of service (NULL pointer dereference).(CVE-2016-8887)

The jp2_cdef_destroy function in jp2_cod.c in JasPer before 2.0.13 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted image.(CVE-2017-6850)

The jp2_colr_destroy function in jp2_cod.c in JasPer before 1.900.13 allows remote attackers to cause a denial of service (NULL pointer dereference) by leveraging incorrect cleanup of JP2 box data on error. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-8887.(CVE-2016-10250)

Heap-based buffer overflow in the jpc_dec_decodepkt function in jpc_t2dec.c in JasPer 2.0.10 allows remote attackers to have unspecified impact via a crafted image.(CVE-2017-6852)

Race condition in the jas_stream_tmpfile function in libjasper/base/jas_stream.c in JasPer 1.900.1 allows local users to cause a denial of service (program exit) by creating the appropriate tmp.XXXXXXXXXX temporary file, which causes Jasper to exit. NOTE: this was originally reported as a symlink issue, but this was incorrect. NOTE: some vendors dispute the severity of this issue, but it satisfies CVE's requirements for inclusion.(CVE-2008-3521)");

  script_tag(name:"affected", value:"'jasper' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~33.h6.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
