# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0212");
  script_cve_id("CVE-2021-3468");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 20:03:11 +0000 (Wed, 09 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0212)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0212");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0212.html");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=984938");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28901");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1939614");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/VCPLDL2TVAMUG4CYPGSPUHQ3KJXENCPN/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi' package(s) announced via the MGASA-2021-0212 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Avoid infinite loop by handling HUP event in client_work. (CVE-2021-3468)");

  script_tag(name:"affected", value:"'avahi' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-core7", rpm:"lib64avahi-core7~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-gir0.6", rpm:"lib64avahi-gir0.6~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-ui-gtk3-devel", rpm:"lib64avahi-ui-gtk3-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-ui-gtk3_0", rpm:"lib64avahi-ui-gtk3_0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-ui0", rpm:"lib64avahi-ui0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahicore-gir0.6", rpm:"lib64avahicore-gir0.6~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gir0.6", rpm:"libavahi-gir0.6~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-devel", rpm:"libavahi-ui-gtk3-devel~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3_0", rpm:"libavahi-ui-gtk3_0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui0", rpm:"libavahi-ui0~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahicore-gir0.6", rpm:"libavahicore-gir0.6~0.7~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-core7", rpm:"lib64avahi-core7~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-gir0.6", rpm:"lib64avahi-gir0.6~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-libevent-devel", rpm:"lib64avahi-libevent-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-libevent1", rpm:"lib64avahi-libevent1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-qt5-devel", rpm:"lib64avahi-qt5-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-qt5_1", rpm:"lib64avahi-qt5_1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-ui-gtk3-devel", rpm:"lib64avahi-ui-gtk3-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahi-ui-gtk3_0", rpm:"lib64avahi-ui-gtk3_0~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avahicore-gir0.6", rpm:"lib64avahicore-gir0.6~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gir0.6", rpm:"libavahi-gir0.6~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent-devel", rpm:"libavahi-libevent-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent1", rpm:"libavahi-libevent1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-devel", rpm:"libavahi-qt5-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5_1", rpm:"libavahi-qt5_1~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-devel", rpm:"libavahi-ui-gtk3-devel~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3_0", rpm:"libavahi-ui-gtk3_0~0.8~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahicore-gir0.6", rpm:"libavahicore-gir0.6~0.8~6.1.mga8", rls:"MAGEIA8"))) {
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
