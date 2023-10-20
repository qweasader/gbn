# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0276");
  script_cve_id("CVE-2023-40184");
  script_tag(name:"creation_date", value:"2023-10-02 04:11:57 +0000 (Mon, 02 Oct 2023)");
  script_version("2023-10-02T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-10-02 05:05:22 +0000 (Mon, 02 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-05 14:02:00 +0000 (Tue, 05 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0276)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0276");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0276.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32276");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SOT237TIHTHPX5YNIWLVNINOEYC7WMG2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp' package(s) announced via the MGASA-2023-0276 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In versions prior to 0.9.23 improper handling of session establishment
errors allows bypassing OS-level session restrictions. The
`auth_start_session` function can return non-zero (1) value on, e.g.,
PAM error which may result in in session restrictions such as max
concurrent sessions per user by PAM (ex ./etc/security/limits.conf) to
be bypassed. (CVE-2023-40184)");

  script_tag(name:"affected", value:"'xrdp' package(s) on Mageia 8, Mageia 9.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.9.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.9.23~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.9.23~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.9.23~1.mga9", rls:"MAGEIA9"))) {
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
