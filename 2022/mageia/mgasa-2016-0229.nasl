# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0229");
  script_cve_id("CVE-2016-5104");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0229)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0229");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0229.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18559");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/26/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libimobiledevice, usbmuxd' package(s) announced via the MGASA-2016-0229 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libimobiledevice and usbmuxd package fixes security vulnerability:

The libimobiledevice and libusbmuxd libraries open a socket that listens on all
available network interfaces, rather than just the loopback interface as was
intended (CVE-2016-5104).");

  script_tag(name:"affected", value:"'libimobiledevice, usbmuxd' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64imobiledevice-devel", rpm:"lib64imobiledevice-devel~1.1.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imobiledevice4", rpm:"lib64imobiledevice4~1.1.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbmuxd-devel", rpm:"lib64usbmuxd-devel~1.0.9~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64usbmuxd2", rpm:"lib64usbmuxd2~1.0.9~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimobiledevice", rpm:"libimobiledevice~1.1.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimobiledevice-devel", rpm:"libimobiledevice-devel~1.1.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimobiledevice4", rpm:"libimobiledevice4~1.1.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbmuxd-devel", rpm:"libusbmuxd-devel~1.0.9~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusbmuxd2", rpm:"libusbmuxd2~1.0.9~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-imobiledevice", rpm:"python-imobiledevice~1.1.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usbmuxd", rpm:"usbmuxd~1.0.9~6.1.mga5", rls:"MAGEIA5"))) {
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
