# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884863");
  script_cve_id("CVE-2023-41051");
  script_tag(name:"creation_date", value:"2023-09-23 01:18:16 +0000 (Sat, 23 Sep 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-07 19:19:19 +0000 (Thu, 07 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-8e6ae98f81)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8e6ae98f81");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-8e6ae98f81");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236894");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0056.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firecracker, virtiofsd' package(s) announced via the FEDORA-2023-8e6ae98f81 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebuild dependent packages for vm-memory v0.12.2 to address CVE-2023-41051 / RUSTSEC-2023-0056.

- [link moved to references]
- [link moved to references]");

  script_tag(name:"affected", value:"'firecracker, virtiofsd' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"firecracker", rpm:"firecracker~1.4.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firecracker-debuginfo", rpm:"firecracker-debuginfo~1.4.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firecracker-debugsource", rpm:"firecracker-debugsource~1.4.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtiofsd", rpm:"virtiofsd~1.7.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtiofsd-debuginfo", rpm:"virtiofsd-debuginfo~1.7.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtiofsd-debugsource", rpm:"virtiofsd-debugsource~1.7.0~4.fc39", rls:"FC39"))) {
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
