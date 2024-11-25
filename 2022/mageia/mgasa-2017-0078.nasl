# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0078");
  script_cve_id("CVE-2016-5545", "CVE-2017-3290", "CVE-2017-3316", "CVE-2017-3332", "CVE-2017-3538");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-31 18:54:39 +0000 (Tue, 31 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0078)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0078");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0078.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20222");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2017-0078 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides virtualbox 5.1.18 maintenance release and resolves
at least the following security issues:

A vulnerability in the GUI subcomponent of virtualbox allows unauthenticated
attacker unauthorized update, insert or delete access to some data as well
as unauthorized read access to a subset of VirtualBox accessible data and
unauthorized ability to cause a partial denial of service (bsc#1020856)
(CVE-2016-5545).

A vulnerability in the Shared Folder subcomponent of virtualbox allows high
privileged attacker unauthorized creation, deletion or modification access
to critical data and unauthorized ability to cause a hang or frequently
repeatable crash (bsc#1020856) (CVE-2017-3290).

A vulnerability in the GUI subcomponent of virtualbox allows high privileged
attacker with network access via multiple protocols to compromise virtualbox
(bsc#1020856) (CVE-2017-3316).

A vulnerability in the SVGA Emulation subcomponent of virtualbox allows low
privileged attacker unauthorized creation, deletion or modification access
to critical data and unauthorized ability to cause a hang or frequently
repeatable crash (bsc#1020856) (CVE-2017-3332).

A vulnerability in the Shared Folder subcomponent of virtualbox allows high
privileged attacker unauthorized creation, deletion or modification access
to critical data and unauthorized access to critical data to all virtualbox
accessible data (CVE-2017-3538).

For other fixes in this update, see the referenced changelog.");

  script_tag(name:"affected", value:"'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.50-desktop-2.mga5", rpm:"vboxadditions-kernel-4.4.50-desktop-2.mga5~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.50-desktop586-2.mga5", rpm:"vboxadditions-kernel-4.4.50-desktop586-2.mga5~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.50-server-2.mga5", rpm:"vboxadditions-kernel-4.4.50-server-2.mga5~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-doc", rpm:"virtualbox-doc~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.50-desktop-2.mga5", rpm:"virtualbox-kernel-4.4.50-desktop-2.mga5~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.50-desktop586-2.mga5", rpm:"virtualbox-kernel-4.4.50-desktop586-2.mga5~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.50-server-2.mga5", rpm:"virtualbox-kernel-4.4.50-server-2.mga5~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.1.18~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-vboxvideo", rpm:"x11-driver-video-vboxvideo~5.1.18~1.mga5", rls:"MAGEIA5"))) {
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
