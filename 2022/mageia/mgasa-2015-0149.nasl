# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0149");
  script_cve_id("CVE-2015-1779");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 11:40:00 +0000 (Mon, 05 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0149)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0149");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0149.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15561");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154656.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2015-0149 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated qemu packages fix security vulnerabilities:

A denial of service flaw was found in the way QEMU handled malformed Physical
Region Descriptor Table (PRDT) data sent to the host's IDE and/or AHCI
controller emulation. A privileged guest user could use this flaw to crash the
system (rhbz#1204919).

It was found that the QEMU's websocket frame decoder processed incoming frames
without limiting resources used to process the header and the payload. An
attacker able to access a guest's VNC console could use this flaw to trigger a
denial of service on the host by exhausting all available memory and CPU
(CVE-2015-1779).");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.6.2~1.9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.6.2~1.9.mga4", rls:"MAGEIA4"))) {
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
