# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0253");
  script_cve_id("CVE-2018-9988", "CVE-2018-9989");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-15 13:20:39 +0000 (Tue, 15 May 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0253)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0253");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0253.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22914");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-04/msg00051.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bctoolbox, dolphin-emu, hiawatha, mbedtls, shadowsocks-libev' package(s) announced via the MGASA-2018-0253 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-9988: ARM mbed TLS before 2.1.11, before 2.7.2, and before
2.8.0 has a buffer over-read in ssl_parse_server_key_exchange() that
could cause a crash on invalid input.
CVE-2018-9989: ARM mbed TLS before 2.1.11, before 2.7.2, and before
2.8.0 has a buffer over-read in ssl_parse_server_psk_hint() that could
cause a crash on invalid input.");

  script_tag(name:"affected", value:"'bctoolbox, dolphin-emu, hiawatha, mbedtls, shadowsocks-libev' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"bctoolbox", rpm:"bctoolbox~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dolphin-emu", rpm:"dolphin-emu~5.0~5.2.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hiawatha", rpm:"hiawatha~10.4~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bctoolbox-devel", rpm:"lib64bctoolbox-devel~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bctoolbox-tester0", rpm:"lib64bctoolbox-tester0~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bctoolbox0", rpm:"lib64bctoolbox0~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls-devel", rpm:"lib64mbedtls-devel~2.7.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls10", rpm:"lib64mbedtls10~2.7.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64shadowsocks-devel", rpm:"lib64shadowsocks-devel~3.1.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64shadowsocks2", rpm:"lib64shadowsocks2~3.1.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbctoolbox-devel", rpm:"libbctoolbox-devel~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbctoolbox-tester0", rpm:"libbctoolbox-tester0~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbctoolbox0", rpm:"libbctoolbox0~0.2.0~4.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls-devel", rpm:"libmbedtls-devel~2.7.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls10", rpm:"libmbedtls10~2.7.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libshadowsocks-devel", rpm:"libshadowsocks-devel~3.1.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libshadowsocks2", rpm:"libshadowsocks2~3.1.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mbedtls", rpm:"mbedtls~2.7.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadowsocks-libev", rpm:"shadowsocks-libev~3.1.0~1.2.mga6", rls:"MAGEIA6"))) {
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
