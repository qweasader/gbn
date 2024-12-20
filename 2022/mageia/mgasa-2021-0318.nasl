# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0318");
  script_cve_id("CVE-2021-27218", "CVE-2021-27219", "CVE-2021-28153");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 16:44:22 +0000 (Thu, 25 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0318");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0318.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28520");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4759-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4764-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the MGASA-2021-0318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Krzesimir Nowak discovered that GLib incorrectly handled certain large
buffers. A remote attacker could use this issue to cause applications linked
to GLib to crash, resulting in a denial of service, or possibly execute
arbitrary code (CVE-2021-27218).

Kevin Backhouse discovered that GLib incorrectly handled certain memory
allocations. A remote attacker could use this issue to cause applications
linked to GLib to crash, resulting in a denial of service, or possibly execute
arbitrary code (CVE-2021-27219).

It was discovered that GLib incorrectly handled certain symlinks when
replacing files. If a user or automated system were tricked into extracting a
specially crafted file with File Roller, a remote attacker could possibly
create files outside of the intended directory (CVE-2021-28153).");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0", rpm:"glib2.0~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0-static-devel", rpm:"lib64glib2.0-static-devel~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0-static-devel", rpm:"libglib2.0-static-devel~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.60.2~1.5.mga7", rls:"MAGEIA7"))) {
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
