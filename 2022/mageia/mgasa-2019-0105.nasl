# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0105");
  script_cve_id("CVE-2019-6690");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-02 15:37:39 +0000 (Tue, 02 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0105");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0105.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24341");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-02/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-gnupg' package(s) announced via the MGASA-2019-0105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When symmetric encryption is used, data can be injected through the
passphrase property of the gnupg.GPG.encrypt() and gnupg.GPG.decrypt()
methods. The supplied passphrase is not validated for newlines, and the
library passes --passphrase-fd=0 to the gpg executable, which expects the
passphrase on the first line of stdin, and the ciphertext to be decrypted
or plaintext to be encrypted on subsequent lines. By supplying a passphrase
containing a newline an attacker can control/modify the ciphertext/plaintext
being decrypted/encrypted (CVE-2019-6690).");

  script_tag(name:"affected", value:"'python-gnupg' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-gnupg", rpm:"python-gnupg~0.4.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gnupg", rpm:"python3-gnupg~0.4.4~1.mga6", rls:"MAGEIA6"))) {
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
