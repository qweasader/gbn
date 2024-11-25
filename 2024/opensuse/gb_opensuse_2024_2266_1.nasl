# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856278");
  script_version("2024-07-24T05:06:37+0000");
  script_cve_id("CVE-2024-4317");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 04:00:34 +0000 (Wed, 10 Jul 2024)");
  script_name("openSUSE: Security Advisory for postgresql16 (SUSE-SU-2024:2266-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2266-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6Z73UBUW45SOQ5DVECC232MM2TPN2AZU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql16'
  package(s) announced via the SUSE-SU-2024:2266-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql16 fixes the following issues:

  PostgreSQL upgrade to version 16.3 (bsc#1224051):

  * CVE-2024-4317: Fixed visibility restriction of pg_stats_ext and
      pg_stats_ext_exprs entries to the table owner (bsc#1224038).

  Bug fixes:

  * Fix incompatibility with LLVM 18.

  * Prepare for PostgreSQL 17.

  * Make sure all compilation and doc generation happens in %build.

  * Require LLVM  = 17 for now, because LLVM 18 doesn't seem to work.

  * Remove constraints file because improved memory usage for s390x

  * Use %patch -P N instead of deprecated %patchN.");

  script_tag(name:"affected", value:"'postgresql16' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl", rpm:"postgresql16-plperl~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython", rpm:"postgresql16-plpython~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-mini", rpm:"postgresql16-devel-mini~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel", rpm:"postgresql16-server-devel~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debuginfo", rpm:"postgresql16-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-debuginfo", rpm:"postgresql16-devel-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-mini-debuginfo", rpm:"postgresql16-devel-mini-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib", rpm:"postgresql16-contrib~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-test", rpm:"postgresql16-test~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debugsource", rpm:"postgresql16-debugsource~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl-debuginfo", rpm:"postgresql16-pltcl-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-mini-debugsource", rpm:"postgresql16-mini-debugsource~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server", rpm:"postgresql16-server~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl-debuginfo", rpm:"postgresql16-plperl-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel-debuginfo", rpm:"postgresql16-server-devel-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel", rpm:"postgresql16-devel~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit-devel", rpm:"postgresql16-llvmjit-devel~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython-debuginfo", rpm:"postgresql16-plpython-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-debuginfo", rpm:"postgresql16-server-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl", rpm:"postgresql16-pltcl~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib-debuginfo", rpm:"postgresql16-contrib-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit", rpm:"postgresql16-llvmjit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit-debuginfo", rpm:"postgresql16-llvmjit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit-debuginfo", rpm:"libecpg6-32bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit-debuginfo", rpm:"libpq5-32bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-docs", rpm:"postgresql16-docs~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-64bit-debuginfo", rpm:"libpq5-64bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-64bit-debuginfo", rpm:"libecpg6-64bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-64bit", rpm:"libpq5-64bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-64bit", rpm:"libecpg6-64bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl", rpm:"postgresql16-plperl~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython", rpm:"postgresql16-plpython~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-mini", rpm:"postgresql16-devel-mini~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel", rpm:"postgresql16-server-devel~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debuginfo", rpm:"postgresql16-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-debuginfo", rpm:"postgresql16-devel-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel-mini-debuginfo", rpm:"postgresql16-devel-mini-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib", rpm:"postgresql16-contrib~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-test", rpm:"postgresql16-test~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debugsource", rpm:"postgresql16-debugsource~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl-debuginfo", rpm:"postgresql16-pltcl-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-mini-debugsource", rpm:"postgresql16-mini-debugsource~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server", rpm:"postgresql16-server~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl-debuginfo", rpm:"postgresql16-plperl-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel-debuginfo", rpm:"postgresql16-server-devel-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel", rpm:"postgresql16-devel~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit-devel", rpm:"postgresql16-llvmjit-devel~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython-debuginfo", rpm:"postgresql16-plpython-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-debuginfo", rpm:"postgresql16-server-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl", rpm:"postgresql16-pltcl~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib-debuginfo", rpm:"postgresql16-contrib-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit", rpm:"postgresql16-llvmjit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-llvmjit-debuginfo", rpm:"postgresql16-llvmjit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit-debuginfo", rpm:"libecpg6-32bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit-debuginfo", rpm:"libpq5-32bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-docs", rpm:"postgresql16-docs~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-64bit-debuginfo", rpm:"libpq5-64bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-64bit-debuginfo", rpm:"libecpg6-64bit-debuginfo~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-64bit", rpm:"libpq5-64bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-64bit", rpm:"libecpg6-64bit~16.2~150600.16.2.1", rls:"openSUSELeap15.6"))) {
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
