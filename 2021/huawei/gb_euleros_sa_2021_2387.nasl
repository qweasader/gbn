# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2387");
  script_cve_id("CVE-2017-5503", "CVE-2017-5504", "CVE-2017-5505", "CVE-2021-26926", "CVE-2021-3443", "CVE-2021-3467");
  script_tag(name:"creation_date", value:"2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-22 16:09:00 +0000 (Mon, 22 Mar 2021)");

  script_name("Huawei EulerOS: Security Advisory for jasper (EulerOS-SA-2021-2387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2387");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2387");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'jasper' package(s) announced via the EulerOS-SA-2021-2387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in jasper before 2.0.25. An out of bounds read issue was found in jp2_decode function which may lead to disclosure of information or program crash.(CVE-2021-26926)

The dec_clnpass function in libjasper/jpc/jpc_t1dec.c in JasPer 1.900.27 allows remote attackers to cause a denial of service (invalid memory write and crash) or possibly have unspecified other impact via a crafted image.(CVE-2017-5503)

The jpc_undo_roi function in libjasper/jpc/jpc_dec.c in JasPer 1.900.27 allows remote attackers to cause a denial of service (invalid memory read and crash) via a crafted image.(CVE-2017-5504)

The jas_matrix_asl function in jas_seq.c in JasPer 1.900.27 allows remote attackers to cause a denial of service (invalid memory read and crash) via a crafted image.(CVE-2017-5505)

A NULL pointer dereference flaw was found in the way Jasper versions before 2.0.27 handled component references in the JP2 image format decoder. A specially crafted JP2 image file could cause an application using the Jasper library to crash when opened.(CVE-2021-3443)

A NULL pointer dereference flaw was found in the way Jasper versions before 2.0.26 handled component references in CDEF box in the JP2 image format decoder. A specially crafted JP2 image file could cause an application using the Jasper library to crash when opened.(CVE-2021-3467)");

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

  if(!isnull(res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~33.h9", rls:"EULEROS-2.0SP2"))) {
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
