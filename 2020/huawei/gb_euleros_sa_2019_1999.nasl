# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1999");
  script_cve_id("CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538");
  script_tag(name:"creation_date", value:"2020-01-23 12:30:27 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2019-1999)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1999");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1999");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2019-1999 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the pxa2xx_ssp_load function in hw/arm/pxa2xx.c in QEMU before 1.7.2 allows remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted s->rx_level value in a savevm image.(CVE-2013-4533)

Multiple buffer overflows in the ssd0323_load function in hw/display/ssd0323.c in QEMU before 1.7.2 allow remote attackers to cause a denial of service (memory corruption) or possibly execute arbitrary code via crafted (1) cmd_len, (2) row, or (3) col values, (4) row_start and row_end values, or (5) col_star and col_end values in a savevm image.(CVE-2013-4538)

The ssi_sd_transfer function in hw/sd/ssi-sd.c in QEMU before 1.7.2 allows remote attackers to execute arbitrary code via a crafted arglen value in a savevm image.(CVE-2013-4537)

Buffer overflow in hw/intc/openpic.c in QEMU before 1.7.2 allows remote attackers to cause a denial of service or possibly execute arbitrary code via vectors related to IRQDest elements.(CVE-2013-4534)");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~156.5.h3", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~156.5.h3", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~156.5.h3", rls:"EULEROS-2.0SP3"))) {
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
