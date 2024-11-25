# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0311");
  script_cve_id("CVE-2024-34397");
  script_tag(name:"creation_date", value:"2024-09-26 04:11:43 +0000 (Thu, 26 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0311)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0311");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0311.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33198");
  script_xref(name:"URL", value:"https://lwn.net/Articles/975988/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6768-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/05/07/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the MGASA-2024-0311 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in GNOME GLib before 2.78.5, and 2.79.x and
2.80.x before 2.80.1. When a GDBus-based client subscribes to signals
from a trusted system service such as NetworkManager on a shared
computer, other users of the same computer can send spoofed D-Bus
signals that the GDBus-based client will wrongly interpret as having
been sent by the trusted system service. This could lead to the
GDBus-based client behaving incorrectly, with an application-dependent
impact. (CVE-2024-34397)");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0", rpm:"glib2.0~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0-tests", rpm:"glib2.0-tests~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0-static-devel", rpm:"lib64glib2.0-static-devel~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0-static-devel", rpm:"libglib2.0-static-devel~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.76.3~1.2.mga9", rls:"MAGEIA9"))) {
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
