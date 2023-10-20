# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0019");
  script_cve_id("CVE-2020-12845");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-23 22:15:00 +0000 (Wed, 23 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0019");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0019.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cherokee' package(s) announced via the MGASA-2021-0019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cherokee 0.4.27 to 1.2.104 is affected by a denial of service due to a NULL
pointer dereferences. A remote unauthenticated attacker can crash the server
by sending an HTTP request to protected resources using a malformed
Authorization header that is mishandled during a cherokee_buffer_add call
within cherokee_validator_parse_basic or cherokee_validator_parse_digest.
(CVE-2020-12845).");

  script_tag(name:"affected", value:"'cherokee' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"cget", rpm:"cget~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cherokee", rpm:"cherokee~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cherokee-devel", rpm:"cherokee-devel~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cherokee-base0", rpm:"lib64cherokee-base0~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cherokee-client0", rpm:"lib64cherokee-client0~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cherokee-server0", rpm:"lib64cherokee-server0~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcherokee-base0", rpm:"libcherokee-base0~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcherokee-client0", rpm:"libcherokee-client0~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcherokee-server0", rpm:"libcherokee-server0~1.2.103~17.1.mga7", rls:"MAGEIA7"))) {
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
