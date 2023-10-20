# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0475");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2020-0475)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0475");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0475.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27700");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/11/30/1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7S5MEH3CXBXVT2KJAPUZFFUHVVXK6BN7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdeconnect-kde' package(s) announced via the MGASA-2020-0475 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"For the pairing procedure, the GUI component only presented the friendly
'deviceName' to identify peer devices, which is completely under attacker
control. Furthermore the 'deviceName' is transmitted in cleartext in UDP
broadcast messages for all other nodes in the network segment to see.
Therefore malicious devices can attempt to confuse users by requesting a
pairing under the same 'deviceName' to gain access to a system.

Now, a sha256 fingerprint of the concatenated public keys of the two involved
certificates is displayed. In the initial popup, a prefix of 8 hex digits of
the fingerprint is displayed. The full fingerprint is reachable via an
additional 'view key' button.");

  script_tag(name:"affected", value:"'kdeconnect-kde' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"kdeconnect-kde", rpm:"kdeconnect-kde~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeconnect-kde-handbook", rpm:"kdeconnect-kde-handbook~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdeconnect-kde-nautilus", rpm:"kdeconnect-kde-nautilus~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeconnectcore1", rpm:"lib64kdeconnectcore1~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeconnectinterfaces1", rpm:"lib64kdeconnectinterfaces1~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeconnectpluginkcm1", rpm:"lib64kdeconnectpluginkcm1~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeconnectcore1", rpm:"libkdeconnectcore1~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeconnectinterfaces1", rpm:"libkdeconnectinterfaces1~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeconnectpluginkcm1", rpm:"libkdeconnectpluginkcm1~1.3.4~2.2.mga7", rls:"MAGEIA7"))) {
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
