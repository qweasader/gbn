# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0172");
  script_cve_id("CVE-2014-2286", "CVE-2014-2287");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0172");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0172.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2014-001.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2014-002.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13061");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'asterisk' package(s) announced via the MGASA-2014-0172 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated asterisk packages fix security vulnerabilities:

In Asterisk before 11.8.1, sending a HTTP request that is handled by Asterisk
with a large number of Cookie headers could overflow the stack. You could
even exhaust memory if you sent an unlimited number of headers in the request
(CVE-2014-2286).

In Asterisk before 11.8.1, an attacker can use all available file descriptors
using SIP INVITE requests. Each INVITE meeting certain conditions will leak a
channel and several file descriptors. The file descriptors cannot be released
without restarting Asterisk which may allow intrusion detection systems to be
bypassed by sending the requests slowly (CVE-2014-2287).");

  script_tag(name:"affected", value:"'asterisk' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"asterisk", rpm:"asterisk~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-addons", rpm:"asterisk-addons~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-devel", rpm:"asterisk-devel~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-firmware", rpm:"asterisk-firmware~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-gui", rpm:"asterisk-gui~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-alsa", rpm:"asterisk-plugins-alsa~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-calendar", rpm:"asterisk-plugins-calendar~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-cel", rpm:"asterisk-plugins-cel~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-corosync", rpm:"asterisk-plugins-corosync~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-curl", rpm:"asterisk-plugins-curl~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-dahdi", rpm:"asterisk-plugins-dahdi~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-fax", rpm:"asterisk-plugins-fax~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-festival", rpm:"asterisk-plugins-festival~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-ices", rpm:"asterisk-plugins-ices~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-jabber", rpm:"asterisk-plugins-jabber~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-jack", rpm:"asterisk-plugins-jack~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-ldap", rpm:"asterisk-plugins-ldap~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-lua", rpm:"asterisk-plugins-lua~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-minivm", rpm:"asterisk-plugins-minivm~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-mobile", rpm:"asterisk-plugins-mobile~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-mp3", rpm:"asterisk-plugins-mp3~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-mysql", rpm:"asterisk-plugins-mysql~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-ooh323", rpm:"asterisk-plugins-ooh323~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-osp", rpm:"asterisk-plugins-osp~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-oss", rpm:"asterisk-plugins-oss~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-pgsql", rpm:"asterisk-plugins-pgsql~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-pktccops", rpm:"asterisk-plugins-pktccops~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-portaudio", rpm:"asterisk-plugins-portaudio~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-radius", rpm:"asterisk-plugins-radius~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-saycountpl", rpm:"asterisk-plugins-saycountpl~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-skinny", rpm:"asterisk-plugins-skinny~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-snmp", rpm:"asterisk-plugins-snmp~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-speex", rpm:"asterisk-plugins-speex~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-sqlite", rpm:"asterisk-plugins-sqlite~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-tds", rpm:"asterisk-plugins-tds~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-unistim", rpm:"asterisk-plugins-unistim~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-voicemail", rpm:"asterisk-plugins-voicemail~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-voicemail-imap", rpm:"asterisk-plugins-voicemail-imap~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-voicemail-plain", rpm:"asterisk-plugins-voicemail-plain~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64asteriskssl1", rpm:"lib64asteriskssl1~11.8.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasteriskssl1", rpm:"libasteriskssl1~11.8.1~1.mga4", rls:"MAGEIA4"))) {
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
