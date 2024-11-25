# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856267");
  script_version("2024-07-10T14:21:44+0000");
  script_cve_id("CVE-2023-38469", "CVE-2023-38471");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 19:58:27 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-06-29 04:07:42 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for avahi (SUSE-SU-2024:2200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2200-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CPLP2CD22FBI6QP5VOX64JD6NXMAXJYN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi'
  package(s) announced via the SUSE-SU-2024:2200-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for avahi fixes the following issues:

  * CVE-2023-38471: Fixed a reachable assertion in dbus_set_host_name.
      (bsc#1216594)

  * CVE-2023-38469: Fixed a reachable assertion in
      avahi_dns_packet_append_record. (bsc#1216598)

  ##");

  script_tag(name:"affected", value:"'avahi' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python3-avahi", rpm:"python3-avahi~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-devel", rpm:"libavahi-qt5-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debugsource", rpm:"avahi-debugsource~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Avahi-0_6", rpm:"typelib-1_0-Avahi-0_6~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-debuginfo", rpm:"libdns_sd-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-autoipd", rpm:"avahi-autoipd~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0-debuginfo", rpm:"libavahi-gobject0-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-avahi-gtk", rpm:"python3-avahi-gtk~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-devel", rpm:"libavahi-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd", rpm:"libdns_sd~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-debuginfo", rpm:"libavahi-common3-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent1", rpm:"libavahi-libevent1~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-debuginfo", rpm:"avahi-utils-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-1", rpm:"libavahi-qt5-1~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-0-debuginfo", rpm:"libavahi-ui-gtk3-0-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhowl0", rpm:"libhowl0~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-0", rpm:"libavahi-ui-gtk3-0~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils", rpm:"avahi-utils~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-debuginfo", rpm:"libavahi-glib1-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-glib2-debugsource", rpm:"avahi-glib2-debugsource~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-debuginfo", rpm:"libavahi-client3-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhowl0-debuginfo", rpm:"libhowl0-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7-debuginfo", rpm:"libavahi-core7-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-1-debuginfo", rpm:"libavahi-qt5-1-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-gtk-debuginfo", rpm:"avahi-utils-gtk-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-autoipd-debuginfo", rpm:"avahi-autoipd-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent1-debuginfo", rpm:"libavahi-libevent1-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-qt5-debugsource", rpm:"avahi-qt5-debugsource~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-compat-mDNSResponder-devel", rpm:"avahi-compat-mDNSResponder-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-gtk", rpm:"avahi-utils-gtk~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-32bit-debuginfo", rpm:"libavahi-glib1-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-32bit-debuginfo", rpm:"avahi-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-32bit", rpm:"libavahi-glib1-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-32bit-debuginfo", rpm:"libdns_sd-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-32bit", rpm:"libavahi-common3-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-32bit-debuginfo", rpm:"libavahi-client3-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-32bit", rpm:"libdns_sd-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-32bit", rpm:"libavahi-client3-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-32bit-debuginfo", rpm:"libavahi-common3-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-lang", rpm:"avahi-lang~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-64bit-debuginfo", rpm:"libavahi-common3-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-64bit", rpm:"libdns_sd-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-64bit-debuginfo", rpm:"avahi-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-64bit-debuginfo", rpm:"libdns_sd-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-64bit-debuginfo", rpm:"libavahi-glib1-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-64bit", rpm:"libavahi-glib1-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-64bit-debuginfo", rpm:"libavahi-client3-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-64bit", rpm:"libavahi-common3-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-64bit", rpm:"libavahi-client3-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-avahi", rpm:"python3-avahi~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-devel", rpm:"libavahi-qt5-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debugsource", rpm:"avahi-debugsource~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Avahi-0_6", rpm:"typelib-1_0-Avahi-0_6~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-debuginfo", rpm:"libdns_sd-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-autoipd", rpm:"avahi-autoipd~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0-debuginfo", rpm:"libavahi-gobject0-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-avahi-gtk", rpm:"python3-avahi-gtk~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-devel", rpm:"libavahi-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd", rpm:"libdns_sd~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-debuginfo", rpm:"libavahi-common3-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent1", rpm:"libavahi-libevent1~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-debuginfo", rpm:"avahi-utils-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-1", rpm:"libavahi-qt5-1~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-0-debuginfo", rpm:"libavahi-ui-gtk3-0-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhowl0", rpm:"libhowl0~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-0", rpm:"libavahi-ui-gtk3-0~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils", rpm:"avahi-utils~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-debuginfo", rpm:"libavahi-glib1-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-glib2-debugsource", rpm:"avahi-glib2-debugsource~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-debuginfo", rpm:"libavahi-client3-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhowl0-debuginfo", rpm:"libhowl0-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7-debuginfo", rpm:"libavahi-core7-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-qt5-1-debuginfo", rpm:"libavahi-qt5-1-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-gtk-debuginfo", rpm:"avahi-utils-gtk-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-autoipd-debuginfo", rpm:"avahi-autoipd-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent1-debuginfo", rpm:"libavahi-libevent1-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-qt5-debugsource", rpm:"avahi-qt5-debugsource~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-compat-mDNSResponder-devel", rpm:"avahi-compat-mDNSResponder-devel~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-gtk", rpm:"avahi-utils-gtk~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-32bit-debuginfo", rpm:"libavahi-glib1-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-32bit-debuginfo", rpm:"avahi-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-32bit", rpm:"libavahi-glib1-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-32bit-debuginfo", rpm:"libdns_sd-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-32bit", rpm:"libavahi-common3-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-32bit-debuginfo", rpm:"libavahi-client3-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-32bit", rpm:"libdns_sd-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-32bit", rpm:"libavahi-client3-32bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-32bit-debuginfo", rpm:"libavahi-common3-32bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-lang", rpm:"avahi-lang~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-64bit-debuginfo", rpm:"libavahi-common3-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-64bit", rpm:"libdns_sd-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-64bit-debuginfo", rpm:"avahi-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-64bit-debuginfo", rpm:"libdns_sd-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-64bit-debuginfo", rpm:"libavahi-glib1-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-64bit", rpm:"libavahi-glib1-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-64bit-debuginfo", rpm:"libavahi-client3-64bit-debuginfo~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-64bit", rpm:"libavahi-common3-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-64bit", rpm:"libavahi-client3-64bit~0.8~150600.15.3.1", rls:"openSUSELeap15.6"))) {
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