# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0021");
  script_cve_id("CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0021");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0021.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23663");
  script_xref(name:"URL", value:"https://openafs.org/pages/security/OPENAFS-SA-2018-001.txt");
  script_xref(name:"URL", value:"https://openafs.org/pages/security/OPENAFS-SA-2018-002.txt");
  script_xref(name:"URL", value:"https://openafs.org/pages/security/OPENAFS-SA-2018-003.txt");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.23/RELNOTES-1.6.23");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4302");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openafs' package(s) announced via the MGASA-2019-0021 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeffrey Altman reported that the backup tape controller (butc) process
does accept incoming RPCs but does not require (or allow for)
authentication of those RPCs, allowing an unauthenticated attacker to
perform volume operations with administrator credentials
(CVE-2018-16947).

Mark Vitale reported that several RPC server routines do not fully
initialize output variables, leaking memory contents (from both the
stack and the heap) to the remote caller for otherwise-successful RPCs
(CVE-2018-16948).

Mark Vitale reported that an unauthenticated attacker can consume large
amounts of server memory and network bandwidth via specially crafted
requests, resulting in denial of service to legitimate clients
(CVE-2018-16949).");

  script_tag(name:"affected", value:"'openafs' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-static-devel", rpm:"lib64openafs-static-devel~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-static-devel", rpm:"libopenafs-static-devel~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.6.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.6.23~1.mga6", rls:"MAGEIA6"))) {
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
