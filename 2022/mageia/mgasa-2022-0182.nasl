# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0182");
  script_cve_id("CVE-2022-24761");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-28 17:00:00 +0000 (Mon, 28 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0182)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0182");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0182.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30248");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5364-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-waitress' package(s) announced via the MGASA-2022-0182 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When using Waitress versions 2.1.0 and prior behind a proxy that does not
properly validate the incoming HTTP request matches the RFC7230 standard,
Waitress and the frontend proxy may disagree on where one request starts
and where it ends. This would allow requests to be smuggled via the
front-end proxy to waitress and later behavior. There are two classes of
vulnerability that may lead to request smuggling that are addressed by
this advisory: The use of Python's `int()` to parse strings into integers,
leading to `+10` to be parsed as `10`, or `0x01` to be parsed as `1`,
where as the standard specifies that the string should contain only digits
or hex digits, and Waitress does not support chunk extensions, however it
was discarding them without validating that they did not contain illegal
characters. This vulnerability has been patched in Waitress 2.1.1");

  script_tag(name:"affected", value:"'python-waitress' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-waitress", rpm:"python-waitress~2.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-waitress", rpm:"python3-waitress~2.1.1~1.mga8", rls:"MAGEIA8"))) {
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
