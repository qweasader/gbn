# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885632");
  script_cve_id("CVE-2023-40032");
  script_tag(name:"creation_date", value:"2024-01-30 02:04:48 +0000 (Tue, 30 Jan 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-15 14:49:31 +0000 (Fri, 15 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-5c3c77b8eb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5c3c77b8eb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-5c3c77b8eb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2098477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238469");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vips' package(s) announced via the FEDORA-2024-5c3c77b8eb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 8.15.1, security fix for CVE-2023-40032");

  script_tag(name:"affected", value:"'vips' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"vips", rpm:"vips~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-debuginfo", rpm:"vips-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-debugsource", rpm:"vips-debugsource~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-devel", rpm:"vips-devel~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-doc", rpm:"vips-doc~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-heif", rpm:"vips-heif~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-heif-debuginfo", rpm:"vips-heif-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-jxl", rpm:"vips-jxl~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-jxl-debuginfo", rpm:"vips-jxl-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-magick", rpm:"vips-magick~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-magick-debuginfo", rpm:"vips-magick-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-openslide", rpm:"vips-openslide~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-openslide-debuginfo", rpm:"vips-openslide-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-poppler", rpm:"vips-poppler~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-poppler-debuginfo", rpm:"vips-poppler-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-tools", rpm:"vips-tools~8.15.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vips-tools-debuginfo", rpm:"vips-tools-debuginfo~8.15.1~1.fc39", rls:"FC39"))) {
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
