# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0320");
  script_cve_id("CVE-2017-5837", "CVE-2017-5839", "CVE-2017-5842", "CVE-2017-5844");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-13 22:23:18 +0000 (Mon, 13 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0320");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0320.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/02/02/9");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20236");
  script_xref(name:"URL", value:"https://lwn.net/Alerts/714996/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer0.10-plugins-base, gstreamer1.0-plugins-base' package(s) announced via the MGASA-2017-0320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Denial of service in GStreamer base plugins can be caused by floating
point exceptions (CVE-2017-5837, CVE-2017-5844), stack overflow
(CVE-2017-5839), or out-of-bounds heap read (CVE-2017-5842).

Note that GStreamer 0.10 was only affected by the floating point
exceptions.");

  script_tag(name:"affected", value:"'gstreamer0.10-plugins-base, gstreamer1.0-plugins-base' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-cdparanoia", rpm:"gstreamer0.10-cdparanoia~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-gnomevfs", rpm:"gstreamer0.10-gnomevfs~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-libvisual", rpm:"gstreamer0.10-libvisual~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer0.10-plugins-base", rpm:"gstreamer0.10-plugins-base~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdparanoia", rpm:"gstreamer1.0-cdparanoia~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libvisual", rpm:"gstreamer1.0-libvisual~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-base", rpm:"gstreamer1.0-plugins-base~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir0.10", rpm:"lib64gstreamer-plugins-base-gir0.10~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir1.0", rpm:"lib64gstreamer-plugins-base-gir1.0~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10-devel", rpm:"lib64gstreamer-plugins-base0.10-devel~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10_0", rpm:"lib64gstreamer-plugins-base0.10_0~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0-devel", rpm:"lib64gstreamer-plugins-base1.0-devel~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0_0", rpm:"lib64gstreamer-plugins-base1.0_0~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir0.10", rpm:"libgstreamer-plugins-base-gir0.10~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir1.0", rpm:"libgstreamer-plugins-base-gir1.0~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10-devel", rpm:"libgstreamer-plugins-base0.10-devel~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10_0", rpm:"libgstreamer-plugins-base0.10_0~0.10.36~9.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0-devel", rpm:"libgstreamer-plugins-base1.0-devel~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0_0", rpm:"libgstreamer-plugins-base1.0_0~1.4.3~2.2.mga5", rls:"MAGEIA5"))) {
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
