# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0019");
  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16424", "CVE-2018-16425", "CVE-2018-16426", "CVE-2018-16427");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-11 22:15:00 +0000 (Wed, 11 Sep 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0019");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0019.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23447");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FELOINZJEHXTJ757WSU4HYL5HWENARJH/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the MGASA-2019-0019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several buffer overflows when handling responses from a Muscle Card in
muscle_list_files in libopensc/card-muscle.c in OpenSC before 0.19.0-rc1
could be used by attackers able to supply crafted smartcards to cause a
denial of service (application crash) or possibly have unspecified other
impact (CVE-2018-16391).

Several buffer overflows when handling responses from a TCOS Card in
tcos_select_file in libopensc/card-tcos.c in OpenSC before 0.19.0-rc1
could be used by attackers able to supply crafted smartcards to cause a
denial of service (application crash) or possibly have unspecified other
impact (CVE-2018-16392).

Several buffer overflows when handling responses from a Gemsafe V1
Smartcard in gemsafe_get_cert_len in libopensc/pkcs15-gemsafeV1.c in
OpenSC before 0.19.0-rc1 could be used by attackers able to supply
crafted smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact (CVE-2018-16393).

A buffer overflow when handling string concatenation in util_acl_to_str
in tools/util.c in OpenSC before 0.19.0-rc1 could be used by attackers
able to supply crafted smartcards to cause a denial of service
(application crash) or possibly have unspecified other impact
(CVE-2018-16418).

Several buffer overflows when handling responses from a Cryptoflex card
in read_public_key in tools/cryptoflex-tool.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted smartcards
to cause a denial of service (application crash) or possibly have
unspecified other impact (CVE-2018-16419).

Several buffer overflows when handling responses from an ePass 2003 Card
in decrypt_response in libopensc/card-epass2003.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted smartcards
to cause a denial of service (application crash) or possibly have
unspecified other impact (CVE-2018-16420).

Several buffer overflows when handling responses from a CAC Card in
cac_get_serial_nr_from_CUID in libopensc/card-cac.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted smartcards
to cause a denial of service (application crash) or possibly have
unspecified other impact (CVE-2018-16421).

A single byte buffer overflow when handling responses from an esteid
Card in sc_pkcs15emu_esteid_init in libopensc/pkcs15-esteid.c in OpenSC
before 0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to cause a denial of service (application crash) or possibly
have unspecified other impact (CVE-2018-16422).

A double free when handling responses from a smartcard in
sc_file_set_sec_attr in libopensc/sc.c in OpenSC before 0.19.0-rc1 could
be used by attackers able to supply crafted smartcards to cause a denial
of service (application crash) or possibly have unspecified other impact
(CVE-2018-16423).

A double free when handling responses in read_file in
tools/egk-tool.c (aka the eGK card tool) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'opensc' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc-devel", rpm:"lib64opensc-devel~0.19.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc6", rpm:"lib64opensc6~0.19.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smm-local6", rpm:"lib64smm-local6~0.19.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc-devel", rpm:"libopensc-devel~0.19.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc6", rpm:"libopensc6~0.19.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmm-local6", rpm:"libsmm-local6~0.19.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.19.0~1.mga6", rls:"MAGEIA6"))) {
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
