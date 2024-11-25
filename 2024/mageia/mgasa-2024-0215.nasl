# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0215");
  script_cve_id("CVE-2024-4453");
  script_tag(name:"creation_date", value:"2024-06-10 04:12:25 +0000 (Mon, 10 Jun 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0215");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0215.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33259");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2024-0002.html");
  script_xref(name:"URL", value:"https://lwn.net/Articles/976177/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1.0-plugins-base' package(s) announced via the MGASA-2024-0215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer EXIF Metadata Parsing Integer Overflow Remote Code Execution
Vulnerability. This vulnerability allows remote attackers to execute
arbitrary code on affected installations of GStreamer. Interaction with
this library is required to exploit this vulnerability but attack
vectors may vary depending on the implementation. The specific flaw
exists within the parsing of EXIF metadata. The issue results from the
lack of proper validation of user-supplied data, which can result in an
integer overflow before allocating a buffer. An attacker can leverage
this vulnerability to execute code in the context of the current
process. (CVE-2024-4453)");

  script_tag(name:"affected", value:"'gstreamer1.0-plugins-base' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdparanoia", rpm:"gstreamer1.0-cdparanoia~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libvisual", rpm:"gstreamer1.0-libvisual~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-base", rpm:"gstreamer1.0-plugins-base~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl-gir1.0", rpm:"lib64gstgl-gir1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir1.0", rpm:"lib64gstreamer-plugins-base-gir1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0-devel", rpm:"lib64gstreamer-plugins-base1.0-devel~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0_0", rpm:"lib64gstreamer-plugins-base1.0_0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-gir1.0", rpm:"libgstgl-gir1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir1.0", rpm:"libgstreamer-plugins-base-gir1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0-devel", rpm:"libgstreamer-plugins-base1.0-devel~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0_0", rpm:"libgstreamer-plugins-base1.0_0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
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
