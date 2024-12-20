# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822281");
  script_version("2024-10-10T07:25:31+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2022-07-31 01:15:13 +0000 (Sun, 31 Jul 2022)");
  script_name("Fedora: Security Advisory for golang-github-yuin-gopher-lua (FEDORA-2022-37aef44d1e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-37aef44d1e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/73ZOAAW3RNJBD5XOCOAE3AVJIUT2545C");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-yuin-gopher-lua'
  package(s) announced via the FEDORA-2022-37aef44d1e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GopherLua is a Lua5.1 VM and compiler written in Go. GopherLua has a same goal
with Lua: Be a scripting language with extensible semantics. It provides Go
APIs that allow you to easily embed a scripting language to your Go host
programs.");

  script_tag(name:"affected", value:"'golang-github-yuin-gopher-lua' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-yuin-gopher-lua-0", rpm:"golang-github-yuin-gopher-lua-0~24.20220305gitf4c35e4.fc36", rls:"FC36"))) {
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